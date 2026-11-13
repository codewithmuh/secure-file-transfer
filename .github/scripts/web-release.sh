#!/usr/bin/env bash
# The web app's release (ADR-0008, ADR-0005, #283): the logic behind .github/workflows/web.yml, web-deploy.yml and the
# web part of promote.yml's promotion-gate, kept here so .github/scripts/test-web-release.sh can dry-run it without
# GitHub or AWS.
#
# A build of main publishes one versioned bundle to the shared account's store (infra/modules/web-bundles):
# bundles/<git-sha>/<path> for each file, then bundles/<git-sha>/manifest.json, which lists every file with its
# SHA-256, size, content type and cache header. Each environment's pointer, deploy/environments/<env>/web.yaml, names a
# version and its manifest's digest, as a cluster's values file names an image digest. Promotion copies the previous
# environment's pointer; rollback reverts it; either way, merging it deploys: web-deploy.yml copies that version into
# the environment's web buckets, Osaka first, and writes index.html last. Nothing else moves. Zeros mean "never
# released".
#
# Usage:
#   web-release.sh get ENV [REF]           the version and digest ENV's pointer names, in the work tree or at a Git ref
#   web-release.sh set ENV VERSION DIGEST  point ENV at VERSION, whose manifest has DIGEST
#   web-release.sh copy FROM TO            point TO where FROM points; prints the version and digest
#   web-release.sh gate BASE HEAD          what a pull request changes in the pointers, checked (promotion-gate)
#   web-release.sh manifest DIST VERSION   the manifest of a built bundle (web/dist), on stdout
#   web-release.sh digest FILE             sha256:<hex> of FILE
#   web-release.sh publish DIST MANIFEST VERSION
#                                          upload a bundle once; prints the stored manifest's digest (needs AWS: the
#                                          shared account's publish role, WEB_BUNDLE_BUCKET)
#   web-release.sh deploy ENV              copy ENV's version into its web buckets (needs AWS: the environment's
#                                          release role, WEB_BUNDLE_BUCKET, WEB_ACCOUNT_ID, WEB_CONFIG)
#   web-release.sh served ENV              the version and digest ENV's web app serves now, from its release.json
#                                          (needs SFT_DOMAIN)
#   web-release.sh open-pr ENV             commit ENV's pointer as the bot and open or update its pull request (needs
#                                          GH_TOKEN, BOT_SLUG)
set -euo pipefail

readonly ENVIRONMENTS="dev staging prod"
readonly ZERO_VERSION="0000000000000000000000000000000000000000"
readonly ZERO_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
readonly VERSION_RE='^[0-9a-f]{40}$'
readonly DIGEST_RE='^sha256:[0-9a-f]{64}$'
# The files an environment writes itself, never part of a bundle (ADR-0008: one bundle for every environment).
readonly OWN_FILES="config.json release.json"

die() {
  echo "web-release: $*" >&2
  exit 1
}

known_env() {
  case " $ENVIRONMENTS " in
    *" $1 "*) return 0 ;;
    *) die "unknown environment '$1' (expected one of: $ENVIRONMENTS)" ;;
  esac
}

previous_env() {
  case $1 in
    staging) echo dev ;;
    prod) echo staging ;;
    *) echo "" ;;
  esac
}

pointer() { echo "deploy/environments/$1/web.yaml"; }

# The version and digest in a pointer file, read from stdin. Fails unless each appears exactly once, well formed.
read_pointer() {
  local name=$1 text version digest
  text=$(cat)
  version=$(sed -n 's/^version: *\([^ #]*\).*$/\1/p' <<<"$text")
  digest=$(sed -n 's/^manifest: *\([^ #]*\).*$/\1/p' <<<"$text")
  [[ $(grep -c '^version:' <<<"$text") == 1 && $(grep -c '^manifest:' <<<"$text") == 1 ]] ||
    die "$name: needs exactly one 'version:' and one 'manifest:' line"
  [[ $version =~ $VERSION_RE ]] || die "$name: version '$version' is not a 40-character Git SHA"
  [[ $digest =~ $DIGEST_RE ]] || die "$name: manifest '$digest' is not sha256:<64 hex>"
  echo "$version $digest"
}

cmd_get() {
  local env=$1 ref=${2:-} file
  known_env "$env"
  file=$(pointer "$env")
  if [[ -n $ref ]]; then
    git show "$ref:$file" 2>/dev/null | read_pointer "$file" || die "no $file at $ref"
  else
    [[ -f $file ]] || die "no $file"
    # shellcheck disable=SC2094 # the first "$file" is only the name read_pointer prints in errors
    read_pointer "$file" <"$file"
  fi
}

cmd_set() {
  local env=$1 version=$2 digest=$3 file tmp
  known_env "$env"
  [[ $version =~ $VERSION_RE && $version != "$ZERO_VERSION" ]] || die "'$version' is not a released version"
  [[ $digest =~ $DIGEST_RE && $digest != "$ZERO_DIGEST" ]] || die "'$digest' is not a manifest digest"
  file=$(pointer "$env")
  # shellcheck disable=SC2094 # as above; the shape must be right before anything is written
  read_pointer "$file" <"$file" >/dev/null
  tmp=$(mktemp)
  sed -e "s/^version: *[0-9a-f]*/version: $version/" -e "s/^manifest: *sha256:[0-9a-f]*/manifest: $digest/" "$file" >"$tmp"
  cat "$tmp" >"$file" # keeps the file's mode
  rm -f "$tmp"
}

cmd_copy() {
  local from=$1 to=$2 current version digest
  known_env "$from"
  known_env "$to"
  [[ $(previous_env "$to") == "$from" ]] || die "$to is promoted from $(previous_env "$to"), not $from"
  current=$(cmd_get "$from") # apart from read, so a failure stops here
  read -r version digest <<<"$current"
  [[ $version != "$ZERO_VERSION" ]] || die "$from has never been released; nothing to promote"
  cmd_set "$to" "$version" "$digest"
  echo "$version $digest"
}

# Every pointer ENV had on main up to REF, first parents only.
pinned_before() {
  local env=$1 ref=$2 commit file
  file=$(pointer "$env")
  for commit in $(git log --first-parent --format=%H "$ref" -- "$file"); do
    git show "$commit:$file" 2>/dev/null | read_pointer "$file" 2>/dev/null || true
  done | sort -u
}

# What promotion-gate decides for a pull request from BASE to HEAD, as promotion.sh does for image digests. A pull
# request may move one environment's pointer at most. Prints nothing if it moves none, or one line:
#   <env> build                        dev: a new build, which the web workflow opened
#   <env> rollback                     a pointer this environment had before on main (a revert): passes at once
#   <env> promote <prev> <version>     the pointer the previous environment has on main (BASE): the workflow then
#                                      checks that the previous environment serves it
# Fails for anything else: two environments at once, a pointer the previous environment doesn't have, the zeros.
cmd_gate() {
  local base=$1 head=$2 fork env new old changed="" target="" prev history
  fork=$(git merge-base "$base" "$head") || die "$base and $head share no history"
  for env in $ENVIRONMENTS; do
    git cat-file -e "$head:$(pointer "$env")" 2>/dev/null || continue
    git diff --quiet "$fork" "$head" -- "$(pointer "$env")" && continue
    new=$(cmd_get "$env" "$head")
    old="$ZERO_VERSION $ZERO_DIGEST"
    if git cat-file -e "$base:$(pointer "$env")" 2>/dev/null; then old=$(cmd_get "$env" "$base"); fi
    [[ $new == "$old" ]] && continue
    [[ $new != "$ZERO_VERSION"* && $new != *"$ZERO_DIGEST" ]] || die "$env: the zeros can't be deployed"
    changed+="${changed:+ }$env"
    target=$env
  done
  [[ -n $changed ]] || return 0
  [[ $changed != *" "* ]] || die "the pull request moves the web pointers of $changed; promote one environment per pull request"

  new=$(cmd_get "$target" "$head")
  prev=$(previous_env "$target")
  if [[ -z $prev ]]; then
    echo "$target build"
    return
  fi
  history=$(pinned_before "$target" "$base")
  if grep -qxF "$new" <<<"$history"; then
    echo "$target rollback"
    return
  fi
  [[ $new == "$(cmd_get "$prev" "$base")" ]] ||
    die "$target: ${new%% *} is neither what $prev points at on main nor a version $target ran before; promote only by copying $prev"
  echo "$target promote $prev ${new%% *}"
}

content_type() {
  case $1 in
    *.html) echo "text/html; charset=utf-8" ;;
    *.js | *.mjs) echo "text/javascript; charset=utf-8" ;;
    *.css) echo "text/css; charset=utf-8" ;;
    *.json | *.map) echo "application/json" ;;
    *.webmanifest) echo "application/manifest+json" ;;
    *.svg) echo "image/svg+xml" ;;
    *.png) echo "image/png" ;;
    *.jpg | *.jpeg) echo "image/jpeg" ;;
    *.webp) echo "image/webp" ;;
    *.ico) echo "image/x-icon" ;;
    *.woff2) echo "font/woff2" ;;
    *.woff) echo "font/woff" ;;
    *.txt) echo "text/plain; charset=utf-8" ;;
    *) return 1 ;;
  esac
}

# Vite names what it builds under assets/ by content hash, so those never change and are cached for a year; every
# other file (index.html, the public/ files) is revalidated on each load (ADR-0008).
cache_control() {
  case $1 in
    assets/*) echo "public, max-age=31536000, immutable" ;;
    *) echo "no-cache" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

cmd_digest() {
  [[ -f $1 ]] || die "no file $1"
  echo "sha256:$(sha256_of "$1")"
}

cmd_manifest() {
  local dist=$1 version=$2 path type
  [[ -d $dist ]] || die "no directory $dist"
  [[ $version =~ $VERSION_RE ]] || die "'$version' is not a 40-character Git SHA"
  [[ -f $dist/index.html ]] || die "$dist has no index.html: is it a build?"
  (cd "$dist" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) | while IFS= read -r path; do
    case " $OWN_FILES " in *" $path "*) continue ;; esac
    [[ $path != *[[:space:]]* && $path != *'"'* && $path != *\\* ]] || die "$path: an odd file name"
    type=$(content_type "$path") || die "$path: no content type for its extension; add one to web-release.sh"
    jq -cn --arg path "$path" --arg sha "$(sha256_of "$dist/$path")" --argjson size "$(wc -c <"$dist/$path" | tr -d ' ')" \
      --arg type "$type" --arg cache "$(cache_control "$path")" \
      '{path: $path, sha256: $sha, size: $size, content_type: $type, cache_control: $cache}'
  done | jq -cs --arg version "$version" '{version: $version, files: .}'
}

# ---- AWS ------------------------------------------------------------------------------------------------------------

# The base64 of a hex SHA-256, which S3 checks the bytes against on upload.
# shellcheck disable=SC2001 # every pair of hex digits becomes a \x escape: one sed, not a loop
checksum() { printf '%b' "$(sed 's/../\\x&/g' <<<"$1")" | base64; }

# Prints nothing when the object doesn't exist, fails on any other error, so a denied call is never "not there".
head_object() {
  local bucket=$1 key=$2 errors status=0
  errors=$(mktemp)
  aws s3api head-object --bucket "$bucket" --key "$key" --output json 2>"$errors" || status=$?
  if [[ $status != 0 ]]; then
    if grep -qE '\(404\)|Not Found' "$errors"; then
      rm -f "$errors"
      return 0
    fi
    cat "$errors" >&2
    rm -f "$errors"
    die "can't look up s3://$bucket/$key"
  fi
  rm -f "$errors"
  echo found
}

put_file() { # BUCKET KEY FILE CONTENT_TYPE CACHE_CONTROL SHA256_HEX
  aws s3api put-object --bucket "$1" --key "$2" --body "$3" --content-type "$4" --cache-control "$5" \
    --checksum-sha256 "$(checksum "$6")" --output json >/dev/null
}

cmd_publish() {
  local dist=$1 manifest=$2 version=$3 bucket=${WEB_BUNDLE_BUCKET:?} prefix stored path sha type cache
  [[ $version =~ $VERSION_RE ]] || die "'$version' is not a 40-character Git SHA"
  [[ $(jq -r .version "$manifest") == "$version" ]] || die "$manifest is not version $version's"
  prefix="bundles/$version"
  # Build once: a re-run of this commit finds its finished bundle, whose manifest was written last, and keeps it.
  if [[ -n $(head_object "$bucket" "$prefix/manifest.json") ]]; then
    stored=$(mktemp)
    aws s3api get-object --bucket "$bucket" --key "$prefix/manifest.json" "$stored" >/dev/null
    [[ $(jq -r .version "$stored") == "$version" ]] || die "s3://$bucket/$prefix/manifest.json names another version"
    echo "Bundle $version is already published; keeping it." >&2
    cmd_digest "$stored"
    rm -f "$stored"
    return
  fi
  while IFS=$'\t' read -r path sha type cache; do
    [[ $(sha256_of "$dist/$path") == "$sha" ]] || die "$dist/$path doesn't match its manifest"
    put_file "$bucket" "$prefix/$path" "$dist/$path" "$type" "$cache" "$sha"
  done < <(jq -r '.files[] | [.path, .sha256, .content_type, .cache_control] | @tsv' "$manifest")
  put_file "$bucket" "$prefix/manifest.json" "$manifest" "application/json" "no-cache" "$(sha256_of "$manifest")"
  echo "Published bundle $version ($(jq '.files | length' "$manifest") files)." >&2
  cmd_digest "$manifest"
}

# The environment's web buckets, Osaka's first (ADR-0008); dev has Tokyo's only (modules/edge).
web_buckets() {
  local env=$1 account=$2
  if [[ $env == dev ]]; then
    echo "sft-$env-apne1-web-$account"
  else
    echo "sft-$env-apne3-web-$account sft-$env-apne1-web-$account"
  fi
}

# config.json, which the environment writes and the bundle never holds (web/src/lib/config.ts checks the same shape).
check_config() {
  jq -e '
    (keys == ["apiOrigin", "signInOrigin", "ssoSignIn", "uploadOrigin"])
    and (.apiOrigin | type == "string" and test("^https://[a-z0-9.-]+/v1$"))
    and (.signInOrigin | type == "string" and test("^https://[a-z0-9.-]+$"))
    and (.uploadOrigin | type == "string" and test("^https://[a-z0-9.-]+$"))
    and (.ssoSignIn | type == "boolean")
  ' >/dev/null <<<"$1" || die "WEB_CONFIG must be {apiOrigin: https://<host>/v1, signInOrigin, uploadOrigin: https://<host>, ssoSignIn: true|false}"
}

cmd_deploy() {
  local env=$1 store=${WEB_BUNDLE_BUCKET:?} account=${WEB_ACCOUNT_ID:?} config=${WEB_CONFIG:?}
  local current version digest work prefix path sha type cache bucket buckets
  known_env "$env"
  [[ $account =~ ^[0-9]{12}$ ]] || die "WEB_ACCOUNT_ID is not an account ID"
  check_config "$config"
  current=$(cmd_get "$env")
  read -r version digest <<<"$current"
  if [[ $version == "$ZERO_VERSION" ]]; then
    echo "$env has never been released; nothing to deploy." >&2
    return
  fi
  work=$(mktemp -d)
  prefix="bundles/$version"
  # The manifest Git pins, then every file it lists, each checked before anything is written.
  aws s3api get-object --bucket "$store" --key "$prefix/manifest.json" "$work/manifest.json" >/dev/null
  [[ $(cmd_digest "$work/manifest.json") == "$digest" ]] || die "the stored manifest of $version isn't the one $env pins ($digest)"
  [[ $(jq -r .version "$work/manifest.json") == "$version" ]] || die "the manifest of $version names another version"
  while IFS=$'\t' read -r path sha; do
    mkdir -p "$(dirname "$work/files/$path")"
    aws s3api get-object --bucket "$store" --key "$prefix/$path" "$work/files/$path" >/dev/null
    [[ $(sha256_of "$work/files/$path") == "$sha" ]] || die "$prefix/$path doesn't match the manifest"
  done < <(jq -r '.files[] | [.path, .sha256] | @tsv' "$work/manifest.json")
  printf '%s' "$(jq -c . <<<"$config")" >"$work/config.json"
  jq -cn --arg version "$version" --arg manifest "$digest" '{version: $version, manifest: $manifest}' >"$work/release.json"

  buckets=$(web_buckets "$env" "$account")
  # Every file but index.html, and the environment's config.json, into each Region's bucket, Osaka first. Nothing is
  # deleted: the files of the version being replaced stay, so open pages keep loading and a rollback finds them.
  for bucket in $buckets; do
    while IFS=$'\t' read -r path sha type cache; do
      [[ $path == index.html ]] && continue
      put_file "$bucket" "$path" "$work/files/$path" "$type" "$cache" "$sha"
    done < <(jq -r '.files[] | [.path, .sha256, .content_type, .cache_control] | @tsv' "$work/manifest.json")
    put_file "$bucket" config.json "$work/config.json" application/json no-cache "$(sha256_of "$work/config.json")"
  done
  # Then index.html, last in each Region, Osaka first: from this moment browsers load the new version. release.json
  # says what is served, for the promotion gate.
  for bucket in $buckets; do
    put_file "$bucket" index.html "$work/files/index.html" "text/html; charset=utf-8" no-cache \
      "$(sha256_of "$work/files/index.html")"
    put_file "$bucket" release.json "$work/release.json" application/json no-cache "$(sha256_of "$work/release.json")"
  done
  rm -rf "$work"
  echo "$env serves the web app $version ($digest)." >&2
}

# The environment's names in the shared zone: sft.<domain> in prod, <env>.sft.<domain> elsewhere (modules/edge).
app_origin() {
  local env=$1 domain=${SFT_DOMAIN:?SFT_DOMAIN is not set}
  if [[ $env == prod ]]; then echo "https://app.sft.$domain"; else echo "https://app.$env.sft.$domain"; fi
}

cmd_served() {
  local env=$1 release
  known_env "$env"
  release=$(curl --fail --silent --show-error --max-time 10 "$(app_origin "$env")/release.json") ||
    die "$env's web app doesn't answer release.json"
  jq -er '"\(.version) \(.manifest)"' <<<"$release" || die "$env's release.json isn't one the deploy job wrote"
}

# ---- GitHub (needs GH_TOKEN, the bot's token, and BOT_SLUG) ----------------------------------------------------------

# Commits ENV's pointer on promote-web/<env> as the bot and opens its pull request, or updates the open one: one branch
# per environment, so a newer build replaces an older proposal. The bot's token makes CI run on it (#6).
cmd_open_pr() {
  local env=$1 branch="promote-web/$1" bot="${BOT_SLUG:?}[bot]" bot_id title body auth number prev current version digest
  : "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
  known_env "$env"
  current=$(cmd_get "$env")
  read -r version digest <<<"$current"
  prev=$(previous_env "$env")
  title="chore: promote the web app ${version:0:12} to $env"
  if [[ -z $prev ]]; then
    body="Points dev at the web app built from $version (manifest \`$digest\`)."
  else
    body="Points $env at the web app built from $version (manifest \`$digest\`), copied from $prev. \`promotion-gate\` passes only once $prev serves it."
  fi
  body+=$'\n\n'"Opened by the web release workflow (ADR-0008, #283). Merging it deploys: web-deploy.yml copies the bundle into $env's web buckets and writes index.html last. Roll back by reverting the merge commit."

  if git diff --quiet -- "$(pointer "$env")"; then
    echo "$env already points at $version on main; no pull request." >&2
    return
  fi

  # The token goes in a header, the way actions/checkout passes it, never in the URL or the Git config.
  auth=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')
  local -a git_auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $auth")
  bot_id=$(gh api "users/${BOT_SLUG}%5Bbot%5D" --jq .id)
  git switch -C "$branch"
  git add -- "$(pointer "$env")"
  git -c user.name="$bot" -c user.email="${bot_id}+${bot}@users.noreply.github.com" \
    commit --quiet -m "$title" -m "Built-From: $version"
  git "${git_auth[@]}" push --force --quiet "https://github.com/${GITHUB_REPOSITORY}.git" "HEAD:refs/heads/$branch"

  number=$(gh pr list --repo "$GITHUB_REPOSITORY" --head "$branch" --base main --state open --json number --jq '.[0].number // empty')
  if [[ -n $number ]]; then
    gh pr edit "$number" --repo "$GITHUB_REPOSITORY" --title "$title" --body "$body" >/dev/null
    echo "Updated pull request #$number." >&2
  else
    gh pr create --repo "$GITHUB_REPOSITORY" --base main --head "$branch" --title "$title" --body "$body"
  fi
}

main() {
  local cmd=${1:-}
  shift || true
  case $cmd in
    get) [[ $# -ge 1 && $# -le 2 ]] || die "usage: get ENV [REF]"; cmd_get "$@" ;;
    set) [[ $# -eq 3 ]] || die "usage: set ENV VERSION DIGEST"; cmd_set "$@" ;;
    copy) [[ $# -eq 2 ]] || die "usage: copy FROM TO"; cmd_copy "$@" ;;
    gate) [[ $# -eq 2 ]] || die "usage: gate BASE HEAD"; cmd_gate "$@" ;;
    manifest) [[ $# -eq 2 ]] || die "usage: manifest DIST VERSION"; cmd_manifest "$@" ;;
    digest) [[ $# -eq 1 ]] || die "usage: digest FILE"; cmd_digest "$@" ;;
    publish) [[ $# -eq 3 ]] || die "usage: publish DIST MANIFEST VERSION"; cmd_publish "$@" ;;
    deploy) [[ $# -eq 1 ]] || die "usage: deploy ENV"; cmd_deploy "$@" ;;
    served) [[ $# -eq 1 ]] || die "usage: served ENV"; cmd_served "$@" ;;
    open-pr) [[ $# -eq 1 ]] || die "usage: open-pr ENV"; cmd_open_pr "$@" ;;
    *) die "unknown command '$cmd' (see the header of $0)" ;;
  esac
}

main "$@"
