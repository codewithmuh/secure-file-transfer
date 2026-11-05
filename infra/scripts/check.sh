#!/usr/bin/env bash
# Static checks for infra/, run the same way locally (make infra-check) and in CI (.github/workflows/infra.yml).
#
# Usage: infra/scripts/check.sh <command>
#   conventions  every root's backend and stack name follow infra/README.md; no override files; no account IDs
#   fmt          terraform fmt -check, with a diff
#   fmt-fix      terraform fmt, rewriting files
#   validate     terraform init -backend=false and validate, for every root
#   tflint       tflint with the AWS ruleset, every root and module (infra/.tflint.hcl)
#   trivy        Trivy's misconfiguration scan (exceptions in .trivyignore.yaml)
#   all          all of the checks above, reporting every failure
#   lock <root>  write the root's .terraform.lock.hcl for every platform in LOCK_PLATFORMS
#
# Every tool runs from a container image pinned by version and digest, so nobody installs Terraform, tflint or Trivy
# and everyone runs the same versions. Nothing here reaches AWS: the containers get no credentials, no AWS config and
# none of the host's environment, init runs with -backend=false, and nothing plans or applies.
set -euo pipefail

# Terraform's version must satisfy required_version in every root (~> 1.17.0).
TERRAFORM_IMAGE="hashicorp/terraform:1.17.1@sha256:a5d5a5a892c98f60fcbfa81eac2a40fc19e7b3fa7719bccae10ff6111d22524a"
TFLINT_IMAGE="ghcr.io/terraform-linters/tflint:v0.65.0@sha256:2788f4d4fc663c0e953b011b01bf443fe5bfce7587ee916e588e6057b85d6359"
TRIVY_IMAGE="aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"

# CI runs linux_amd64; Docker on Apple silicon runs linux_arm64; maintainers on Macs run darwin_arm64.
LOCK_PLATFORMS=(linux_amd64 linux_arm64 darwin_arm64)

# Trivy fails on every severity: the Terraform started with no findings, so each exception is a reviewed entry in
# .trivyignore.yaml (T-76), not a LOW finding nobody reads.
TRIVY_SEVERITY="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"

# Root modules: every directory under infra/ that holds .tf files, except the reusable modules.
roots() {
  find infra -name '*.tf' -not -path 'infra/modules/*' -not -path '*/.terraform/*' -print0 |
    xargs -0 -n1 dirname | sort -u
}

# Runs a tool's container with the repository at /repo, as the calling user. Only the variables named here reach it.
container() {
  local network=$1
  shift
  mkdir -p infra/.terraform/plugin-cache
  docker run --rm --network "$network" --user "$(id -u):$(id -g)" \
    --env HOME=/tmp --env CHECKPOINT_DISABLE=1 --env TF_IN_AUTOMATION=1 \
    --env TF_PLUGIN_CACHE_DIR=/repo/infra/.terraform/plugin-cache \
    --volume "$repo:/repo" --workdir /repo "$@"
}

conventions() {
  local status=0 root stack region block
  while IFS= read -r root; do
    stack=${root#infra/}
    if [[ $stack =~ (ap-northeast-[13]) ]]; then region=${BASH_REMATCH[1]}; else region=ap-northeast-1; fi
    block=$(awk '/^  backend "s3" \{/ { inside = 1 } inside { print } inside && /^  \}/ { exit }' "$root"/*.tf)

    if [[ -z $block ]]; then
      echo "$root: no backend \"s3\" block" >&2
      status=1
      continue
    fi
    grep -Eq "^ *key += \"$stack/terraform\\.tfstate\"$" <<<"$block" ||
      { echo "$root: backend key must be \"$stack/terraform.tfstate\"" >&2; status=1; }
    grep -Eq "^ *region += \"$region\"$" <<<"$block" ||
      { echo "$root: backend region must be \"$region\"" >&2; status=1; }
    grep -Eq '^ *use_lockfile += true$' <<<"$block" ||
      { echo "$root: backend must set use_lockfile = true (S3 native locking, ADR-0005)" >&2; status=1; }
    # Nothing else: the bucket names the account, so it comes from -backend-config; encrypt = true would ask for
    # SSE-S3 instead of the bucket's tfstate key; credentials and roles come from the caller, never the code.
    if sed '1d;$d' <<<"$block" | grep -Ev '^ *(#.*)?$' | grep -Eqv '^ *(key|region|use_lockfile) += '; then
      echo "$root: the backend may set only key, region and use_lockfile (infra/README.md, \"State\")" >&2
      status=1
    fi
    grep -Eq "^ *stack += \"$stack\"$" "$root"/*.tf ||
      { echo "$root: the conventions module call must set stack = \"$stack\"" >&2; status=1; }
  done < <(roots)

  # Terraform merges override files into a root after everything else, so one could replace the backend checked above,
  # or anything else, without showing in the file it changes. None may exist under infra/, committed or not: the
  # backend_override.tf that a bootstrap starts with is deleted before its state moves (infra/README.md).
  local overrides
  overrides=$(find infra -type f -not -path '*/.terraform/*' \
    \( -name override.tf -o -name '*_override.tf' -o -name override.tf.json -o -name '*_override.tf.json' \) | sort)
  if [[ -n $overrides ]]; then
    echo "Terraform override files under infra/ (infra/README.md, \"State\"); remove them:" >&2
    echo "$overrides" >&2
    status=1
  fi

  # Account IDs come in as variables, never in the code. An AWS-owned account (for example a regional registry that
  # serves EKS add-ons, ADR-0021) is allowed on a line marked "aws-owned-account". Image digests (sha256:<hex>) can
  # hold twelve digits in a row, so they are removed before the match.
  local ids
  ids=$(grep -rnE --include='*.tf' --include='*.tfvars' --include='*.hcl' --exclude='.terraform.lock.hcl' \
    --exclude-dir=.terraform '[0-9]{12}' infra | grep -v 'aws-owned-account' |
    sed -E 's/sha256:[0-9a-f]{64}//g' | grep -E '^[^:]+:[0-9]+:.*(^|[^0-9])[0-9]{12}([^0-9]|$)' || true)
  if [[ -n $ids ]]; then
    echo "Possible AWS account IDs in infra/ (pass them as variables):" >&2
    echo "$ids" >&2
    status=1
  fi
  return "$status"
}

fmt() {
  container none "$TERRAFORM_IMAGE" fmt -check -recursive -diff infra
}

fmt_fix() {
  container none "$TERRAFORM_IMAGE" fmt -recursive infra
}

validate() {
  local -a dirs=()
  local d
  while IFS= read -r d; do dirs+=("$d"); done < <(roots)
  # One container for every root, so the provider is downloaded once into the plugin cache. -lockfile=readonly
  # fails if a root's lock file is missing or doesn't match its providers.
  # shellcheck disable=SC2016 # the script runs inside the container
  container bridge --entrypoint sh "$TERRAFORM_IMAGE" -c '
    status=0
    for d in "$@"; do
      echo "--- $d"
      if ! out=$(terraform -chdir="$d" init -backend=false -input=false -lockfile=readonly -no-color 2>&1); then
        echo "$out"
        status=1
        continue
      fi
      terraform -chdir="$d" validate -no-color || status=1
    done
    exit "$status"
  ' sh "${dirs[@]}"
}

tflint() {
  # The ruleset plugin is downloaded from GitHub and its signature checked; a token avoids API rate limits in CI.
  local token=--env=CHECKPOINT_DISABLE=1 # a harmless default, so the option below is never empty
  [[ -n ${GITHUB_TOKEN:-} ]] && token=--env=GITHUB_TOKEN
  container bridge "$token" --entrypoint sh "$TFLINT_IMAGE" -c '
    tflint --init --config=/repo/infra/.tflint.hcl &&
      tflint --chdir=infra --recursive --config=/repo/infra/.tflint.hcl --format=compact
  '
}

trivy() {
  # --skip-check-update uses the checks built into this Trivy version, so results change only when the image does;
  # Trivy logs "Falling back to embedded checks" as an error, which is expected. The variables are placeholders, an
  # account that can't exist and a reserved domain, so Trivy evaluates every expression; no real account ID is ever
  # needed here. Osaka's data stacks get a placeholder primary for every key class (TF_VAR_primary_key_arns,
  # infra/README.md).
  local key=arn:aws:kms:ap-northeast-1:000000000000:key/mrk-00000000000000000000000000000000 primaries='' class
  for class in files fields database audit logs secrets platform; do primaries+="${primaries:+,}\"$class\":\"$key\""; done
  container none \
    --env TF_VAR_account_id=000000000000 \
    --env TF_VAR_shared_account_id=000000000000 \
    --env TF_VAR_management_account_id=000000000000 \
    --env TF_VAR_domain=example.com \
    --env 'TF_VAR_admin_principal_arn_patterns=["arn:aws:iam::000000000000:role/placeholder-admin"]' \
    --env TF_VAR_tfstate_primary_key_arn="$key" \
    --env TF_VAR_primary_key_arns="{$primaries}" \
    "$TRIVY_IMAGE" config --exit-code 1 --severity "$TRIVY_SEVERITY" --skip-check-update \
    --ignorefile .trivyignore.yaml --skip-dirs '**/.terraform' infra
}

lock() {
  local root=${1:?usage: check.sh lock <root directory>}
  local -a platforms=()
  local p
  for p in "${LOCK_PLATFORMS[@]}"; do platforms+=("-platform=$p"); done
  # shellcheck disable=SC2016 # the script runs inside the container
  container bridge --entrypoint sh "$TERRAFORM_IMAGE" -c '
    d=$1; shift
    terraform -chdir="$d" init -backend=false -input=false -no-color >/dev/null &&
      terraform -chdir="$d" providers lock -no-color "$@"
  ' sh "$root" "${platforms[@]}"
}

all() {
  local status=0 check
  for check in conventions fmt validate tflint trivy; do
    echo "=== $check"
    "$check" || { echo "=== $check failed" >&2; status=1; }
  done
  return "$status"
}

case "${1:-}" in
  conventions | fmt | validate | tflint | trivy | all) "$1" ;;
  fmt-fix) fmt_fix ;;
  lock) lock "${2:-}" ;;
  *)
    sed -n '4,12p' "$0" >&2
    exit 2
    ;;
esac
