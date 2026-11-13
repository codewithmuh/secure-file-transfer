#!/usr/bin/env bash
# Checks for ops/ that need no AWS (docs/operations/disaster-recovery.md, "The scripts"):
# - every drill and teardown script refuses to start without --env and --profile, and refuses --profile default;
# - --execute needs --account-id;
# - every script's dry run goes through all its steps, runs nothing, and writes its log outside the repository;
# - the teardown's dry run lists what it would destroy, in order;
# - failover-values.sh's changes, on a copy of the values files: each one flips only its keys, and the sequence of a
#   failover and a failback ends where it started.
# Run it with `ops/test.sh`; shellcheck runs separately (`shellcheck ops/*.sh ops/lib/*.sh`).
set -euo pipefail

ops="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$ops/.." && pwd)"
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# expect_refusal <message part> <script> [args...]: the script exits 2 and says why.
expect_refusal() {
  local want="$1" out status
  shift
  set +e
  out="$("$@" 2>&1 </dev/null)"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "$* exited $status, not 2"
  [[ "$out" == *"$want"* ]] || fail "$* didn't say '$want': $out"
}

# An empty PATH entry first, with stand-ins for aws, kubectl, terraform and yq that record any call: a dry run must
# make none.
fake_bin="$(mktemp -d)"
calls="$fake_bin/calls"
for tool in aws kubectl terraform yq; do
  printf '#!/usr/bin/env bash\necho "%s $*" >>"%s"\nexit 1\n' "$tool" "$calls" >"$fake_bin/$tool"
  chmod +x "$fake_bin/$tool"
done
export PATH="$fake_bin:$PATH"
export TMPDIR="$fake_bin"
trap 'rm -rf "$fake_bin"' EXIT

scripts=(
  "regional-failover.sh"
  "regional-failback.sh"
  "az-failure.sh --az apne1-az1"
  "point-in-time-restore.sh --restore-to 2026-11-01T00:00:00Z"
  "teardown.sh"
  "rebuild.sh"
)

for entry in "${scripts[@]}"; do
  read -r -a parts <<<"$entry"
  script="$ops/${parts[0]}"
  extra=("${parts[@]:1}")
  expect_refusal "--env is required" "$script" --profile p "${extra[@]+"${extra[@]}"}"
  expect_refusal "--profile is required" "$script" --env staging "${extra[@]+"${extra[@]}"}"
  expect_refusal "--profile default is refused" "$script" --env staging --profile default "${extra[@]+"${extra[@]}"}"
  expect_refusal "--account-id" "$script" --env staging --profile p --execute "${extra[@]+"${extra[@]}"}"
  expect_refusal "--env must be" "$script" --env qa --profile p "${extra[@]+"${extra[@]}"}"

  rm -f "$calls"
  if ! out="$("$script" --env staging --profile p "${extra[@]+"${extra[@]}"}" 2>&1 </dev/null)"; then
    fail "${parts[0]}'s dry run failed: $out"
    continue
  fi
  [[ ! -s "$calls" ]] || fail "${parts[0]}'s dry run ran: $(cat "$calls")"
  [[ "$out" == *"dry run, nothing runs"* ]] || fail "${parts[0]} didn't say it was a dry run"
  [[ "$out" == *"== done in"* ]] || fail "${parts[0]}'s dry run didn't reach the end"
  log="$(sed -n 's/.*(log: \(.*\))$/\1/p' <<<"$out" | head -1)"
  [[ "$log" == "$fake_bin"/* ]] || fail "${parts[0]}'s dry-run log isn't in the temporary directory: $log"
  grep -q '^| 1 |' "$log" || fail "${parts[0]}'s log has no step rows"
done

# Script-specific refusals.
expect_refusal "dev has no Osaka" "$ops/regional-failover.sh" --env dev --profile p
expect_refusal "--az" "$ops/az-failure.sh" --env staging --profile p
expect_refusal "--restore-to" "$ops/point-in-time-restore.sh" --env staging --profile p

# A drill's dry run prints its marker's push and deletion, and runs neither (docs/runbooks/drill-in-progress.md).
rm -f "$calls"
out="$("$ops/point-in-time-restore.sh" --env staging --profile p --restore-to 2026-11-01T00:00:00Z --drill 2>&1 </dev/null)"
[[ "$out" == *"sft_drill_active 1"* && "$out" == *"-X DELETE"* ]] || fail "the restore drill's dry run has no marker"
[[ ! -s "$calls" ]] || fail "the restore drill's dry run ran: $(cat "$calls")"
expect_refusal "prod has no idle teardown" "$ops/teardown.sh" --env prod --profile p --scope idle
expect_refusal "--last needs --scope final" "$ops/teardown.sh" --env staging --profile p --last
expect_refusal "--inventory needs --account-id" "$ops/teardown.sh" --env staging --profile p --inventory

# The teardown's dry run lists the stacks in order: layer by layer, Osaka then Tokyo, alarms first, network last.
out="$("$ops/teardown.sh" --env prod --profile p --last </dev/null 2>&1)"
listed="$(sed -n 's/^ *[0-9]*\. //p' <<<"$out" | tr '\n' ' ')"
want="environments/prod/ap-northeast-3/alarms environments/prod/ap-northeast-1/alarms environments/prod/ap-northeast-3/cluster-bootstrap"
# prod's dry run checks its prerequisites in the repository (#263): none may be unmet.
[[ "$out" == *"Prerequisites of a prod teardown"* ]] || fail "prod's teardown dry run didn't check its prerequisites"
[[ "$out" != *"UNMET"* ]] || fail "prod's teardown has unmet prerequisites: $(grep UNMET <<<"$out")"
[[ "$out" == *"apply -var teardown=true"*"ap-northeast-3/cluster"* ]] || fail "prod's cluster gets no teardown apply"
[[ "$out" == *"bootstrap/prod/ap-northeast-1 state rm module.terraform_roles.aws_iam_openid_connect_provider.github"* ]] ||
  fail "prod's Tokyo bootstrap keeps the OIDC provider in its state: $out"
[[ "$listed" == *"retained: teardown apply"* ]] || fail "prod's teardown doesn't start with the retained stack"
[[ "$listed" == *"$want"* ]] || fail "teardown order: $listed"
[[ "$listed" == *"environments/prod/ap-northeast-1/network bootstrap/prod/ap-northeast-3 bootstrap/prod/ap-northeast-1 shared "* ]] ||
  fail "teardown's final order: $listed"

# The teardown's parts (#295): the workflow runs the layers as the deploy role, unattended, through the tunnel.
expect_refusal "--part retained is prod's" "$ops/teardown.sh" --env staging --profile p --part retained
expect_refusal "--part bootstrap needs --scope final" "$ops/teardown.sh" --env staging --profile p --part bootstrap
expect_refusal "--unattended takes --part retained or layers" "$ops/teardown.sh" --env prod --profile p \
  --account-id 000000000000 --execute --unattended --log "$fake_bin/refused.md"
rm -f "$calls"
out="$("$ops/teardown.sh" --env staging --profile p --part layers </dev/null 2>&1)"
[[ ! -s "$calls" ]] || fail "the layers teardown's dry run ran: $(cat "$calls")"
[[ "$out" == *"cluster-tunnel.sh open staging ap-northeast-3"*"delete applications.argoproj.io"*"cluster-bootstrap destroy"*"cluster-tunnel.sh close"* ]] ||
  fail "the teardown doesn't drain and destroy cluster-bootstrap through the tunnel: $out"
[[ "$out" == *"not set: TF_VAR_domain"* ]] || fail "the teardown doesn't check the stacks' inputs"
[[ "$out" != *"bootstrap/staging"* ]] || fail "the layers teardown lists a bootstrap stack"
out="$("$ops/teardown.sh" --env prod --profile p --part layers </dev/null 2>&1)"
[[ "$out" != *"retained: teardown apply"* ]] || fail "prod's layers teardown applies the retained stack"
out="$("$ops/teardown.sh" --env prod --profile p --part retained </dev/null 2>&1)"
listed="$(sed -n 's/^ *[0-9]*\. //p' <<<"$out" | tr '\n' ' ')"
[[ "$listed" == *"retained: teardown apply"* && "$listed" != *"environments/prod/ap-northeast"* && "$listed" != *bootstrap* ]] ||
  fail "prod's retained part does more than the retained apply: $listed"

# The rebuild (#295): its refusals, and the order of a staging rebuild and a dev one, which has no Osaka.
expect_refusal "--execute takes --stage stacks or after" "$ops/rebuild.sh" --env staging --profile p \
  --account-id 000000000000 --execute --log "$fake_bin/refused.md"
expect_refusal "--unattended is for --execute" "$ops/rebuild.sh" --env staging --profile p --unattended
expect_refusal "--stage must be" "$ops/rebuild.sh" --env staging --profile p --stage everything
out="$("$ops/rebuild.sh" --env staging --profile p </dev/null 2>&1)"
listed="$(sed -n 's/^ *[0-9]*\. //p' <<<"$out" | tr '\n' ' ')"
want="environments/staging/ap-northeast-1/network environments/staging/ap-northeast-3/network"
want+=" environments/staging/ap-northeast-1/data environments/staging/ap-northeast-3/data"
want+=" environments/staging/ap-northeast-1/data (again, on a first build)"
want+=" environments/staging/ap-northeast-1/network (again: the flow log, once data exists)"
want+=" environments/staging/ap-northeast-3/network (again: the flow log, once data exists)"
want+=" environments/staging/ap-northeast-1/cluster environments/staging/ap-northeast-3/cluster"
want+=" environments/staging/ap-northeast-1/edge environments/staging/ap-northeast-3/edge"
want+=" environments/staging/ap-northeast-1/identity environments/staging/ap-northeast-3/identity "
[[ "$listed" == "$want" ]] || fail "rebuild order: $listed"
[[ "$out" == *"-var osaka_ready=false"* ]] || fail "a first staging build doesn't pass osaka_ready=false"
[[ "$out" == *"TF_VAR_flow_log_destination_arn: the data stack's flow_log_bucket_arn output"* ]] ||
  fail "the rebuild doesn't pass the flow-log bucket to network"
[[ "$out" == *"alarms"*"cluster-tunnel.sh open staging ap-northeast-1"*"create job"*"key-rotation"* ]] ||
  fail "the rebuild's after stage has no first deploy through the tunnel"
out="$("$ops/rebuild.sh" --env dev --profile p </dev/null 2>&1)"
[[ "$out" != *"ap-northeast-3"* ]] || fail "dev's rebuild touches Osaka"
[[ "$out" != *"osaka_ready"* ]] || fail "dev's rebuild passes osaka_ready"

# A missing prerequisite shows as unmet, and --execute refuses: on a copy of the repository without the retained trail.
copy="$(mktemp -d)"
mkdir -p "$copy/ops" "$copy/infra"
cp -R "$ops/." "$copy/ops/"
cp -R "$root/infra/environments" "$root/infra/modules" "$copy/infra/"
rm "$copy/infra/environments/prod/retained/trail.tf"
out="$("$copy/ops/teardown.sh" --env prod --profile p </dev/null 2>&1)"
[[ "$out" == *"UNMET: the retained trail"* ]] || fail "a missing retained trail isn't listed as unmet"
expect_refusal "prerequisite(s) of a prod teardown unmet" "$copy/ops/teardown.sh" --env prod --profile p \
  --account-id 000000000000 --execute
rm -rf "$copy"

# The failback after a detach: its dry run makes the new global database from Osaka's cluster and runs nothing.
rm -f "$calls"
out="$("$ops/regional-failback.sh" --env staging --profile p --after-detach </dev/null 2>&1)"
[[ "$out" == *"create-global-cluster"*"sft-staging-aurora-2"* ]] || fail "the failback after a detach has no new global database"
[[ "$out" == *"TF_VAR_aurora_role=secondary"* ]] || fail "the failback after a detach doesn't set Tokyo's role input"
[[ ! -s "$calls" ]] || fail "the failback's dry run ran: $(cat "$calls")"
# The failback's replay reads Osaka's archive (#276); its generation and outbox jobs keep Tokyo's own.
out="$("$ops/regional-failback.sh" --env staging --profile p </dev/null 2>&1)"
replay="$(grep 'cronjob/recovery.*replay' <<<"$out" || true)"
[[ "$replay" == *apne3-audit-archive* && "$replay" == *AUDIT_ARCHIVE_REGION*ap-northeast-3* ]] ||
  fail "the failback's replay doesn't read Osaka's archive: $replay"
others="$(grep 'cronjob/recovery' <<<"$out" | grep -v replay || true)"
[[ "$(grep -c . <<<"$others")" -eq 2 && "$others" != *AUDIT_ARCHIVE* ]] ||
  fail "the failback's generation and outbox jobs don't read Tokyo's archive: $others"

# failover-values.sh on a copy of the repository's values files.
copy="$(mktemp -d)"
mkdir -p "$copy/ops" "$copy/deploy"
cp "$ops/failover-values.sh" "$copy/ops/"
cp -R "$root/deploy/environments" "$copy/deploy/"
values="$copy/ops/failover-values.sh"
tokyo="$copy/deploy/environments/staging/ap-northeast-1/values.yaml"
osaka="$copy/deploy/environments/staging/ap-northeast-3/values.yaml"
before_tokyo="$(cat "$tokyo")"
before_osaka="$(cat "$osaka")"
state() { "$values" show --env staging | tr '\n' ' '; }

"$values" fence --env staging >/dev/null
[[ "$(cat "$tokyo")" == "$before_tokyo" ]] || fail "fence without --write changed a file"
"$values" fence --env staging --write >/dev/null
[[ "$(state)" == *"ap-northeast-1/values.yaml: pilotLight: true; holdWorkers: false"* ]] || fail "fence, Tokyo: $(state)"
[[ "$(state)" == *"ap-northeast-3/values.yaml: pilotLight: false; holdWorkers: true"* ]] || fail "fence, Osaka: $(state)"
"$values" release-workers --env staging --write >/dev/null
[[ "$(state)" == *"ap-northeast-3/values.yaml: pilotLight: false; holdWorkers: false"* ]] || fail "release: $(state)"
"$values" hold-osaka --env staging --write >/dev/null
"$values" failback --env staging --write >/dev/null
[[ "$(state)" == *"ap-northeast-1/values.yaml: pilotLight: false; holdWorkers: true"* ]] || fail "failback, Tokyo: $(state)"
[[ "$(state)" == *"ap-northeast-3/values.yaml: pilotLight: true; holdWorkers: true"* ]] || fail "failback, Osaka: $(state)"
"$values" release-tokyo --env staging --write >/dev/null
[[ "$(cat "$osaka")" == "$before_osaka" ]] || fail "Osaka's file didn't end where it started"
[[ "$(cat "$tokyo")" == "$before_tokyo" ]] || fail "Tokyo's file didn't end where it started"
# A values file without the block (dev's) gets it appended, and nothing else changes.
dev="$copy/deploy/environments/dev/ap-northeast-1/values.yaml"
before_dev="$(cat "$dev")"
"$values" hold-tokyo --env dev --write >/dev/null
changed="$(diff <(echo "$before_dev") "$dev" || true)"
[[ "$changed" == *"> failover:"* ]] || fail "dev's file didn't get the failover block: $changed"
[[ "$(grep -c '^[<>]' <<<"$changed")" -le 4 ]] || fail "dev's file changed beyond the block: $changed"
expect_refusal "dev has no Osaka" "$values" fence --env dev
# The surviving region's archive (#257): only Osaka's file, only its auditArchive line, and back to "" at failback.
"$values" surviving-osaka --env staging --write >/dev/null
[[ "$(state)" == *'ap-northeast-3/values.yaml: pilotLight: true; holdWorkers: true; survivingRegionOnly: "ap-northeast-3"'* ]] ||
  fail "surviving-osaka: $(state)"
[[ "$(cat "$tokyo")" == "$before_tokyo" ]] || fail "surviving-osaka changed Tokyo's file"
"$values" both-regions --env staging --write >/dev/null
[[ "$(state)" == *'ap-northeast-3/values.yaml: pilotLight: true; holdWorkers: true; survivingRegionOnly: ""'* ]] ||
  fail "both-regions: $(state)"
changed="$(diff <(echo "$before_osaka") "$osaka" || true)"
[[ "$(grep -c '^>' <<<"$changed")" -le 4 && "$(grep -c '^<' <<<"$changed")" -eq 0 ]] ||
  fail "the toggle changed Osaka's file beyond its block: $changed"
rm -rf "$copy"

if ((failures > 0)); then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "ops checks passed"
