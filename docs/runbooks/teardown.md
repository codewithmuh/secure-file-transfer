# Runbook: teardown

Destroying an environment: dev and staging whenever they are idle (NFR-20), and prod at the end of the operating
period, in under an hour, leaving nothing that bills but the retained stack (NFR-19). The order is architecture 3.4's
and infra/README.md's ("Teardown runs the other way"); `ops/teardown.sh` runs it, times it and ends with a tag search
for anything left. Decisions: [disaster-recovery.md](../operations/disaster-recovery.md) section 7.

> [!IMPORTANT]
> **Pending the AWS run.** Staging's idle teardown is the rehearsal. The prerequisites in the repository are met
> (#263): the dry run below lists each and says so.

## Kinds of teardown

| Scope | Environments | What goes | What stays |
|---|---|---|---|
| `idle` | dev, staging | The environment's stacks in both regions | Its bootstrap stacks (state buckets, tfstate keys, key-admin role, about $2 a month), so it can be built again with the same state |
| `final` | prod at the end of the operating period; dev or staging for good | The environment's stacks, then its bootstrap stacks; with `--last`, the shared account's registry | Prod: the retained stack, in the prod account, which stays open until the archive's retention ends ([KEYS] 8.4) |

## List first

A dry run lists every stack in the order it would go, with each command, and runs nothing; for prod it first checks
the prerequisites below that live in the repository, and lists each as met or unmet (`--execute` refuses while one is
unmet). `--inventory` also reads each stack's state and the tag search, read-only:

```bash
ops/teardown.sh --env staging --profile sft-staging-admin
ops/teardown.sh --env staging --profile sft-staging-admin --account-id <account> --inventory
```

## Prerequisites of a prod teardown

- **Rashid's go.** The operating period has ended ([operating-period.md](operating-period.md)), tenants were told,
  and the final drill and load-test reports are written.
- **No file data left to keep.** Transfers and requests have expired or been revoked, and the deletion job has run, so
  the files buckets hold nothing a tenant needs (NFR-8). The data stack's teardown apply then gives prod's files
  buckets the teardown rights dev and staging always have (#42 gap 11, #263): `force_destroy`, and deletes by the
  deploy role and `Admin`, which runs the script. Never before: while prod runs, only the lifecycle jobs delete.
- **The retained stack stands on its own** (#263, checked by the dry run): its own state bucket under the audit key,
  its own deploy role `sft-prod-retained-terraform-deploy` (trusting the `prod-retained` GitHub environment, which
  accepts deployments from main only: a maintainer step in the repository settings), its trail, and its EventBridge
  alerts in both Regions ([retained-stack-change.md](retained-stack-change.md)). Its teardown apply takes the
  environment's workload roles out of the audit key and archive bucket policies, so a role re-created later under the
  same name matches nothing, and turns the key's rotation off ([KEYS] 8.4).
- **Teardown inputs on what prod protects** (checked by the dry run): prod's `cluster`, `identity` and `edge` roots
  take `TF_VAR_teardown=true` to turn deletion protection off, as `data` does.
- `SFT_BUDGET_EMAIL` set: the address the $7 budget emails. `TF_VAR_alert_emails` set: who the retained stack's alert
  topics reach.
- **After a failback that followed a detach**, the global database `sft-prod-aurora-2` was made by the CLI
  ([regional-failback.md](regional-failback.md) step 1): delete it after both data stacks
  (`aws rds delete-global-cluster --global-cluster-identifier sft-prod-aurora-2`).

## Steps

```bash
ops/teardown.sh --env prod --profile sft-prod-admin --account-id <account> --scope final --execute
```

### 0. The retained stack's teardown apply (prod only, 10 min)

`infra/environments/prod/retained` with `TF_VAR_teardown=true`, `TF_VAR_budget_email` and `TF_VAR_alert_emails`: the
key-admin role and the environment's workload roles leave the audit key's and the archive buckets' policies, the key's
rotation stops, the retained trail starts logging management events (the organization trail ends with the shared
account), the GitHub OIDC provider is adopted from prod's bootstrap stack (an `import`, so the retained deploy role
keeps its trust), and the $7 NFR-19 budget is created; it alarms at 50 % actual and 80 % and 100 % actual and
forecast. Turning rotation off pages through `kms-key-destroyed` and `retained-key-changed`: expected, acknowledge
both in the log. Keep `teardown = true` for every later apply: the stack outlives the environment.

### 1. The layers, Osaka first in each

Layer by layer, in reverse of the build: `alarms`, `cluster-bootstrap`, `identity`, `edge`, `cluster`, `data`,
`network`; in each, Osaka then Tokyo. Osaka replicates Tokyo's keys and refers to Tokyo's roles, so it goes first; and
a Tokyo stack that reads an Osaka state (`alarms` reads Osaka's `edge`, `cluster-bootstrap` Osaka's `identity`) goes
before the Osaka stack it reads, which region by region it wouldn't. The security alerts go with
`alarms`, and the KMS key deletions that follow page in prod (`kms-key-destroyed`): expected, acknowledge them.

- **Before `cluster-bootstrap`**, the script deletes what Kubernetes made in AWS outside Terraform: Karpenter's node
  pools (and with them its instances) and every persistent volume claim (the observability stack's volumes).
  Otherwise the VPC can't be destroyed and the volumes go on billing.
- **Before each `data` stack**, an apply with `TF_VAR_teardown=true`: Aurora's deletion protection off, no final
  snapshot, the master secret without a recovery window, and the files buckets' teardown rights (infra/README.md). In
  dev and staging the archive's 1-day governance lock and the 7-day key deletion let the archive go too.
- **Before prod's `cluster`, `identity` and `edge`**, an apply with `TF_VAR_teardown=true`: the EKS cluster's, the user
  pool's and the load balancer's deletion protection off (#263).

### 2. The bootstrap stacks (final only)

Their state bucket, key and key-admin role have `prevent_destroy`. On the teardown branch, set it to `false` in
modules/tfstate-backend and modules/key-admin-role, move each bootstrap root's state back to local (remove the
backend block, `terraform init -migrate-state`), then destroy, Osaka first. The tfstate keys wait out their deletion
window. In prod the script first removes the GitHub OIDC provider from Tokyo's bootstrap state (`terraform state rm`),
so the destroy leaves it to the retained stack, which adopted it in step 0.

### 3. The shared registry (final, last environment only)

With `--last`: `infra/shared`, the registry and its key, goes with the last environment. The organization's log
archive stays under its 90-day Object Lock and bills a few cents until it ends (NFR-19).

### 4. Nothing left (10 min)

The script's tag search lists every resource still tagged with the project and the environment, in Tokyo, Osaka and
us-east-1, and Karpenter's instances and Kubernetes volumes by their own tags. Nothing may remain but resources tagged
`retention = audit-archive` (prod) or nothing at all (dev and staging). The tagging API lists a deleted resource for
a while, so check each hit before calling it a leftover. The time from step 0 to here is NFR-19's teardown time
(≤ 1 hour).

### 5. The bill

The next day, Cost Explorer by the `environment` tag shows nothing but the retained stack for prod (and nothing for an
idle dev or staging); at the month's end, the bill is under $7 (NFR-19) and the build-phase budget's pace is back to
its expected line (capacity 7.3).

## Idle teardown of dev and staging (NFR-20)

When nobody has used dev or staging for a working day, or at the end of a release rehearsal or drill, tear it down:

```bash
ops/teardown.sh --env staging --profile sft-staging-admin --account-id <account> --execute
```

Rebuilding is infra/README.md's apply order against the same bootstrap stacks; capacity A22 expects about 260 billed
hours a month for dev and 162 for staging. Each idle teardown is also a rehearsal of prod's, timed in its log.

[KEYS]: ../security/encryption-and-keys.md
