#!/usr/bin/env bash
# Promotion through Git (ADR-0005, ADR-0007): the logic behind .github/workflows/build.yml and promote.yml, kept here
# so .github/scripts/test-promotion.sh can dry-run it without GitHub or AWS.
#
# The deploy config (#106): each cluster's values file, deploy/environments/<env>/<region>/values.yaml, has a top-level
# `image:` block with exactly one line `  digest: sha256:<64 hex>` (a trailing comment is kept). Promotion edits that
# line and nothing else. Every region of an environment pins the same digest, so Osaka's pilot light runs Tokyo's
# image. `sha256:` and 64 zeros is the placeholder for "never built".
#
# Usage:
#   promotion.sh get ENV [REF]             the digest ENV pins, in the work tree or at a Git ref
#   promotion.sh set ENV DIGEST            pin DIGEST in every region of ENV
#   promotion.sh copy FROM TO              pin FROM's digest in TO
#   promotion.sh should-build BEFORE AFTER AUTHOR BOT
#                                          true or false: does this push to main build an image?
#   promotion.sh gate BASE HEAD            what a pull request changes in the deploy config, checked (promotion-gate)
#   promotion.sh find-build GIT_SHA        the digest tagged GIT_SHA in ECR, or nothing (needs AWS)
#   promotion.sh tag DIGEST TAG            add TAG to DIGEST in ECR; a no-op if it's already there (needs AWS)
#   promotion.sh mark-deployed DIGEST      tag DIGEST deployed-<git-sha> so it never expires; prints the git SHA
#   promotion.sh open-pr ENV DIGEST GIT_SHA
#                                          commit ENV's change as the bot and open or update its pull request
set -euo pipefail

readonly ENVIRONMENTS="dev staging prod"
readonly REPOSITORY="sft/app" # the one application image (ADR-0007)
readonly PLACEHOLDER="sha256:0000000000000000000000000000000000000000000000000000000000000000"
readonly DIGEST_RE='^sha256:[0-9a-f]{64}$'
readonly SHA_RE='^[0-9a-f]{40}$'

die() {
  echo "promotion: $*" >&2
  exit 1
}

previous_env() {
  case $1 in
    staging) echo dev ;;
    prod) echo staging ;;
    *) echo "" ;;
  esac
}

known_env() {
  case " $ENVIRONMENTS " in
    *" $1 "*) return 0 ;;
    *) die "unknown environment '$1' (expected one of: $ENVIRONMENTS)" ;;
  esac
}

# The paths whose changes never build an image. Keep in step with `paths-ignore` in build.yml: the test checks it.
# A path matches the way GitHub's `**` does: `*` in a case pattern matches `/` too.
ignored_path() {
  case $1 in
    deploy/* | docs/* | infra/* | web/* | *.md) return 0 ;;
    *) return 1 ;;
  esac
}

# The digest in one values file, read from stdin. Fails unless the image block has exactly one digest line.
read_digest() {
  local name=$1 lines
  lines=$(awk '
    /^[^[:space:]#]/ { in_image = ($0 ~ /^image:[[:space:]]*(#.*)?$/); next }
    in_image && /^  digest:/ { print }
  ')
  [[ -n $lines ]] || die "$name: no '  digest:' line in the top-level image block"
  [[ $(printf '%s\n' "$lines" | wc -l | tr -d ' ') == 1 ]] || die "$name: more than one digest line in the image block"
  local value=${lines#  digest: }
  value=${value%%#*}
  value=${value%"${value##*[![:space:]]}"}
  [[ $value =~ $DIGEST_RE ]] || die "$name: '$value' is not sha256:<64 hex>"
  echo "$value"
}

# The values files of ENV, one per region, in the work tree or at REF.
values_files() {
  local env=$1 ref=${2:-}
  if [[ -n $ref ]]; then
    git ls-tree -r --name-only "$ref" -- "deploy/environments/$env/" | grep -E '^deploy/environments/[^/]+/[^/]+/values\.yaml$' || true
  else
    for f in deploy/environments/"$env"/*/values.yaml; do
      [[ -f $f ]] && echo "$f"
    done
  fi
}

cmd_get() {
  local env=$1 ref=${2:-} files f digest="" d
  known_env "$env"
  files=$(values_files "$env" "$ref")
  [[ -n $files ]] || die "no deploy/environments/$env/<region>/values.yaml${ref:+ at $ref}"
  for f in $files; do
    if [[ -n $ref ]]; then
      d=$(git show "$ref:$f" | read_digest "$f")
    else
      # shellcheck disable=SC2094 # the first "$f" is only the name read_digest prints in errors
      d=$(read_digest "$f" <"$f")
    fi
    if [[ -z $digest ]]; then
      digest=$d
    elif [[ $d != "$digest" ]]; then
      die "$env's regions pin different digests ($digest and $d in $f); every region must run the same image"
    fi
  done
  echo "$digest"
}

cmd_set() {
  local env=$1 digest=$2 files f tmp
  known_env "$env"
  [[ $digest =~ $DIGEST_RE ]] || die "'$digest' is not sha256:<64 hex>"
  [[ $digest != "$PLACEHOLDER" ]] || die "refusing to pin the placeholder digest"
  files=$(values_files "$env")
  [[ -n $files ]] || die "no deploy/environments/$env/<region>/values.yaml"
  for f in $files; do
    # shellcheck disable=SC2094 # as above; the shape must be right before anything is written
    read_digest "$f" <"$f" >/dev/null
    tmp=$(mktemp)
    awk -v digest="$digest" '
      /^[^[:space:]#]/ { in_image = ($0 ~ /^image:[[:space:]]*(#.*)?$/) }
      in_image && /^  digest:/ { sub(/sha256:[0-9a-f]+/, digest) }
      { print }
    ' "$f" >"$tmp"
    cat "$tmp" >"$f" # keeps the file's mode
    rm -f "$tmp"
  done
}

cmd_copy() {
  local from=$1 to=$2 digest
  known_env "$from"
  known_env "$to"
  [[ $(previous_env "$to") == "$from" ]] || die "$to is promoted from $(previous_env "$to"), not $from"
  digest=$(cmd_get "$from")
  [[ $digest != "$PLACEHOLDER" ]] || die "$from has never been built; nothing to promote"
  cmd_set "$to" "$digest"
  echo "$digest"
}

# A push to main builds unless the bot made it or it changes only ignored paths (ADR-0005). build.yml's paths-ignore
# filter does the same first; this repeats it inside the run, because GitHub runs a workflow whose diff it can't read
# (over 300 files, or a force-push), and the bot check isn't expressible as a trigger filter.
cmd_should_build() {
  local before=$1 after=$2 author=$3 bot=$4 changed f
  if [[ -n $bot && $author == "$bot" ]]; then
    echo "Pushed by $bot, the promotion bot: no build." >&2
    echo false
    return
  fi
  if [[ $before =~ ^0+$ ]] || ! git cat-file -e "${before}^{commit}" 2>/dev/null; then
    echo "No usable base commit: build." >&2
    echo true
    return
  fi
  changed=$(git diff --name-only "$before" "$after")
  while IFS= read -r f; do
    [[ -z $f ]] && continue
    if ! ignored_path "$f"; then
      echo "$f changed: build." >&2
      echo true
      return
    fi
  done <<<"$changed"
  echo "Only deploy config, docs, infra or the web app changed: no build." >&2
  echo false
}

# Every digest ENV's values files have ever pinned on the history of REF.
pinned_before() {
  local env=$1 ref=$2
  git log --format= -p "$ref" -- "deploy/environments/$env/" |
    { grep -oE '^[-+]  digest: sha256:[0-9a-f]{64}' || true; } | sed -E 's/^[-+]  digest: //' | sort -u
}

# What promotion-gate decides for a pull request from BASE to HEAD. Prints one line per environment it changes:
#   <env> build      dev: a new build. CI's checks are dev's gate.
#   <env> rollback   a digest this environment pinned before (a revert): passes at once (ADR-0005).
#   <env> promote <previous env> <digest>
#                    the previous environment's digest: the workflow then checks that environment's health.
# Fails for anything else: a digest the previous environment doesn't pin, regions that disagree, the placeholder.
cmd_gate() {
  local base=$1 head=$2 env old new prev prev_digest history fork
  # Only what the pull request itself changes counts: a branch that is merely behind main changes nothing.
  fork=$(git merge-base "$base" "$head") || die "$base and $head share no history"
  for env in $ENVIRONMENTS; do
    [[ -n $(values_files "$env" "$head") ]] || continue
    git diff --quiet "$fork" "$head" -- "deploy/environments/$env/" && continue
    new=$(cmd_get "$env" "$head")
    old=$PLACEHOLDER
    if [[ -n $(values_files "$env" "$base") ]]; then
      old=$(cmd_get "$env" "$base")
    fi
    [[ $new == "$old" ]] && continue
    [[ $new != "$PLACEHOLDER" ]] || die "$env: the placeholder digest can't be deployed"
    prev=$(previous_env "$env")
    if [[ -z $prev ]]; then
      echo "$env build"
      continue
    fi
    history=$(pinned_before "$env" "$base") # into a variable first: grep -q closing the pipe would trip pipefail
    if grep -qxF "$new" <<<"$history"; then
      echo "$env rollback"
    else
      prev_digest=$(cmd_get "$prev" "$head")
      [[ $new == "$prev_digest" ]] ||
        die "$env: $new is neither $prev's digest ($prev_digest) nor one $env ran before; promote only by copying $prev"
      echo "$env promote $prev $new"
    fi
  done
}

# ---- ECR (needs AWS credentials for the shared account's push role) -------------------------------------------------

cmd_find_build() {
  local sha=$1
  [[ $sha =~ $SHA_RE ]] || die "'$sha' is not a 40-character Git SHA"
  aws ecr describe-images --repository-name "$REPOSITORY" --image-ids "imageTag=$sha" \
    --query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true
}

cmd_tag() {
  local digest=$1 tag=$2 image tags
  [[ $digest =~ $DIGEST_RE ]] || die "'$digest' is not sha256:<64 hex>"
  tags=$(aws ecr describe-images --repository-name "$REPOSITORY" --image-ids "imageDigest=$digest" \
    --query 'imageDetails[0].imageTags' --output json)
  if jq -e --arg t "$tag" 'index($t) != null' <<<"$tags" >/dev/null; then
    echo "$digest already has tag $tag." >&2
    return
  fi
  # Tags are immutable, so a tag is added by putting the same manifest again under the new tag.
  image=$(aws ecr batch-get-image --repository-name "$REPOSITORY" --image-ids "imageDigest=$digest" \
    --accepted-media-types application/vnd.oci.image.index.v1+json application/vnd.oci.image.manifest.v1+json \
    application/vnd.docker.distribution.manifest.list.v2+json application/vnd.docker.distribution.manifest.v2+json \
    --output json)
  [[ $(jq '.images | length' <<<"$image") == 1 ]] || die "$REPOSITORY@$digest is not in ECR"
  aws ecr put-image --repository-name "$REPOSITORY" --image-tag "$tag" --image-digest "$digest" \
    --image-manifest "$(jq -r '.images[0].imageManifest' <<<"$image")" \
    --image-manifest-media-type "$(jq -r '.images[0].imageManifestMediaType' <<<"$image")" >/dev/null
  echo "Tagged $REPOSITORY@$digest as $tag." >&2
}

# ADR-0007's lifecycle keeps every digest tagged deployed-*. One such tag is enough: tags are immutable, and the
# digest stays protected in whichever environment still pins it.
cmd_mark_deployed() {
  local digest=$1 tags sha
  tags=$(aws ecr describe-images --repository-name "$REPOSITORY" --image-ids "imageDigest=$digest" \
    --query 'imageDetails[0].imageTags' --output json)
  sha=$(jq -r '[.[] | select(test("^[0-9a-f]{40}$"))][0] // empty' <<<"$tags")
  [[ -n $sha ]] || die "$REPOSITORY@$digest has no Git SHA tag: it isn't a finished build from main"
  if jq -e '[.[] | select(startswith("deployed-"))] | length > 0' <<<"$tags" >/dev/null; then
    echo "$digest is already tagged deployed." >&2
  else
    cmd_tag "$digest" "deployed-$sha"
  fi
  echo "$sha"
}

# ---- GitHub (needs GH_TOKEN, the bot's token, and BOT_SLUG) ----------------------------------------------------------

# Commits ENV's change on promote/<env> as the bot and opens its pull request, or updates the open one. One branch
# per environment, so a newer build replaces an older proposal instead of queueing behind it. The bot's token makes
# CI run on the pull request (#6).
cmd_open_pr() {
  local env=$1 digest=$2 sha=$3 branch="promote/$1" bot="${BOT_SLUG:?}[bot]" bot_id title body auth number prev
  : "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
  known_env "$env"
  prev=$(previous_env "$env")
  title="chore: promote sft/app ${sha:0:12} to $env"
  if [[ -z $prev ]]; then
    body="Pins dev to \`$REPOSITORY@$digest\`, built from $sha."
  else
    body="Pins $env to \`$REPOSITORY@$digest\`, built from $sha, copied from $prev. \`promotion-gate\` passes only once $prev is synced, healthy and probed on this digest."
  fi
  body+=$'\n\n'"Opened by the promotion workflow (ADR-0005). Merging it deploys: Argo CD syncs the new digest. Roll back by reverting the merge commit."

  if git diff --quiet -- "deploy/environments/$env/"; then
    echo "$env already pins $digest on main; no pull request." >&2
    return
  fi

  # The token goes in a header, the way actions/checkout passes it, never in the URL or the Git config.
  auth=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')
  local -a git_auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $auth")
  local remote="https://github.com/${GITHUB_REPOSITORY}.git" theirs

  # Builds can finish out of order. If the open proposal was built from a newer commit than ours, keep it.
  if git "${git_auth[@]}" fetch --quiet --no-tags "$remote" "+refs/heads/$branch:refs/remotes/proposed/$env" 2>/dev/null; then
    theirs=$(git log -1 --format=%B "refs/remotes/proposed/$env" | sed -n 's/^Built-From: //p')
    if [[ -n $theirs && $theirs != "$sha" ]] && git merge-base --is-ancestor "$sha" "$theirs" 2>/dev/null; then
      echo "$branch already proposes a build of $theirs, which is newer than $sha; leaving it." >&2
      return
    fi
  fi

  bot_id=$(gh api "users/${BOT_SLUG}%5Bbot%5D" --jq .id)
  git switch -C "$branch"
  git add -- "deploy/environments/$env/"
  git -c user.name="$bot" -c user.email="${bot_id}+${bot}@users.noreply.github.com" \
    commit --quiet -m "$title" -m "Built-From: $sha"
  git "${git_auth[@]}" push --force --quiet "$remote" "HEAD:refs/heads/$branch"

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
    set) [[ $# -eq 2 ]] || die "usage: set ENV DIGEST"; cmd_set "$@" ;;
    copy) [[ $# -eq 2 ]] || die "usage: copy FROM TO"; cmd_copy "$@" ;;
    should-build) [[ $# -eq 4 ]] || die "usage: should-build BEFORE AFTER AUTHOR BOT"; cmd_should_build "$@" ;;
    gate) [[ $# -eq 2 ]] || die "usage: gate BASE HEAD"; cmd_gate "$@" ;;
    find-build) [[ $# -eq 1 ]] || die "usage: find-build GIT_SHA"; cmd_find_build "$@" ;;
    tag) [[ $# -eq 2 ]] || die "usage: tag DIGEST TAG"; cmd_tag "$@" ;;
    mark-deployed) [[ $# -eq 1 ]] || die "usage: mark-deployed DIGEST"; cmd_mark_deployed "$@" ;;
    open-pr) [[ $# -eq 3 ]] || die "usage: open-pr ENV DIGEST GIT_SHA"; cmd_open_pr "$@" ;;
    *) die "unknown command '$cmd' (see the header of $0)" ;;
  esac
}

main "$@"
