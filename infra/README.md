# Infrastructure

Terraform for every AWS resource the service uses ([ADR-0005](../docs/adr/0005-terraform-github-actions-argo-cd.md)),
in one AWS account per environment under AWS Organizations ([ADR-0006](../docs/adr/0006-aws-account-per-environment.md)).
Argo CD, not Terraform, owns what runs inside the clusters.

> [!IMPORTANT]
> **Nothing here has been applied.** Until the maintainer names the AWS profiles for each account, Terraform is only
> written and checked statically: fmt, validate, tflint and Trivy ([CLAUDE.md](../CLAUDE.md), delivery plan 4,
> "M4 AWS dev"). No backend points at a real account, nothing has run `terraform plan` or `apply`, and the checks
> below never reach AWS. The commands for applying are written down here so M4 can follow them, not because anyone has
> run them.

## Layout

```
infra/
  bootstrap/<account>/<region>/        state bucket and tfstate key; in Tokyo also the OIDC provider and roles
  organization/                        AWS Organizations, Identity Center, SCPs, budgets (management account, #55)
  shared/                              registry, web bundle artifacts, DNS zone, log archive (shared account)
  environments/<env>/<region>/<layer>/ network, data, cluster, cluster-bootstrap, edge
  environments/prod/retained/          the audit archive and what guards it after teardown (prod only)
  modules/                             reusable modules: every stack is built from these
  scripts/check.sh                     the static checks, locally and in CI
  .tflint.hcl                          tflint rules
```

Each directory outside `modules/` is a **root module** (a stack): its own state, its own plan and apply. Roots are
small and hold only the backend, the providers, the naming and tagging conventions and calls to modules, so Tokyo and
Osaka are built from the same code and the pilot light can't fall behind (T-79).

### Stacks

| Stack | Account | Regions | Holds | Applied by |
|---|---|---|---|---|
| `bootstrap/<account>/ap-northeast-1` | each | Tokyo | The state bucket and tfstate key for Tokyo; the GitHub OIDC provider; the Terraform plan and deploy roles; the key-admin role (none of the last two in the management account) | The maintainer, `Admin` permission set, local state first |
| `bootstrap/<account>/ap-northeast-3` | staging, prod | Osaka | The state bucket for Osaka and the Osaka replica of the tfstate key | The maintainer, `Admin` permission set, local state first |
| `organization` | management | Tokyo (Organizations is global) | Organizations, OUs and accounts, Identity Center and permission sets, SCPs, budgets: [#55](https://github.com/codewithmuh/secure-file-transfer/issues/55) | The maintainer with MFA, never CI; CI plans it read-only (ADR-0006) |
| `shared` | shared | Tokyo, with Osaka and us-east-1 aliases when needed | ECR and the registry key, web bundle artifacts, the public DNS zone, the organization's log archive | CI, `shared` environment |
| `environments/<env>/<region>/<layer>` | dev, staging, prod | dev: Tokyo; staging and prod: Tokyo and Osaka | Architecture 3.1 and 3.2, split into layers (below) | CI, the environment's GitHub environment |
| `environments/prod/retained` | prod | Tokyo, with an Osaka alias | The audit archive buckets and key in both Regions and what guards them after teardown (encryption 8.4) | CI, through its own deploy role; local state first |

| Layer | Holds | Notes |
|---|---|---|
| `network` | VPC, subnets, NAT gateways, VPC endpoints, DNS Firewall (ADR-0021) | Module by [#56](https://github.com/codewithmuh/secure-file-transfer/issues/56) |
| `data` | Aurora, the files buckets, queues, the rate-limit store, the environment's KMS keys; the audit archive in dev and staging | In Osaka, the pilot light's replicas |
| `cluster` | EKS, the `system` node group, Karpenter's IAM, workload roles (ADR-0004) | |
| `cluster-bootstrap` | Argo CD's Helm release (ADR-0005) | Planned and applied only on `main`, through the Systems Manager tunnel (ADR-0021); pull request plans never reach a cluster API |
| `edge` | Load balancer, WAF, the environment's DNS records; in Tokyo, CloudFront and its us-east-1 certificate and web ACL | |
| `retained` | See above | prod only, one root for both Regions |

Every environment layer is a skeleton for now: providers, backend and conventions, with a header comment naming the
issue that fills it. The bootstrap stacks are complete.

Two deliberate exceptions to "one root per Region": `shared` and `retained` each hold a few Osaka (and us-east-1)
resources through provider aliases. Neither is in the failover path, and `retained` is one unit by design: its archive
and key outlive prod and keep their state in their own bucket (encryption 8.4).

### Modules

| Module | What it makes |
|---|---|
| `conventions` | Nothing: names, tags, the state bucket name and the bootstrap role names and ARNs, from the environment, Region and stack. Every root calls it once. |
| `tfstate-backend` | A state bucket and its tfstate key (or, in Osaka, the key's replica) with the bucket and key policies below |
| `terraform-oidc-roles` | The GitHub OIDC provider, the plan role and the deploy role |
| `key-admin-role` | `sft-<env>-keyadmin`, which only BreakGlass may assume (encryption 4.4, rule 6) |
| `network` | [#56](https://github.com/codewithmuh/secure-file-transfer/issues/56) |

## Apply order

1. `bootstrap/management/ap-northeast-1`, before anything else exists.
2. `organization`: creates the member accounts, Identity Center, the `Admin` and `BreakGlass` permission sets and the
   SCPs.
3. For each member account (shared, dev, staging, prod): `bootstrap/<account>/ap-northeast-1`, then, for staging and
   prod, `bootstrap/<account>/ap-northeast-3`, which needs the Tokyo stack's `tfstate_key_arn` output and its roles.
4. `shared`.
5. For each environment, in Tokyo and then in Osaka: `network`, `data`, `cluster`, `cluster-bootstrap`, `edge`. In prod,
   `retained` goes before `data`, because the environment refers to the archive by ARN.

Teardown runs the other way. Prod's `retained` stack stays, and a bootstrap stack goes only when its environment is
destroyed for good: its bucket, key and key-admin role have `prevent_destroy`, which the last apply lifts
(encryption 8.4).

### Bootstrap an account

A bootstrap stack creates the bucket its own state will live in, so it starts with local state. With Terraform 1.17
(`required_version` enforces it), the account's named CLI profile and the `Admin` permission set, never the default
identity:

```bash
cd infra/bootstrap/<account>/<region>
export AWS_PROFILE=<named profile> TF_VAR_account_id=<account id>
# Osaka only: export TF_VAR_tfstate_primary_key_arn=<tfstate_key_arn output of the Tokyo stack>
printf 'terraform {\n  backend "local" {}\n}\n' > backend_override.tf   # git-ignored
terraform init && terraform apply
bucket=$(terraform output -raw state_bucket_name)
rm backend_override.tf
terraform init -migrate-state -backend-config="bucket=$bucket"
rm terraform.tfstate terraform.tfstate.backup               # once the state is in the bucket
```

The management account's stack also needs `TF_VAR_admin_principal_arn_patterns`, the role the maintainer applies it
with, because Identity Center doesn't exist yet the first time.

## State

| | |
|---|---|
| Bucket | One per account and Region: `sft-<env>-<region-short>-tfstate-<account-id>`. Osaka's stacks keep their state in Osaka, so a failover needs nothing from Tokyo (ADR-0005, T-73). The retained stack has its own, `sft-prod-apne1-retained-tfstate-<account-id>`, under the audit key. |
| Key | The root's directory under `infra/`, plus `/terraform.tfstate`: `environments/prod/ap-northeast-3/network/terraform.tfstate`. The `stack` tag has the same value, so a resource names the code that owns it. |
| Locking | S3 native lock files (`use_lockfile = true`): `<key>.tflock` next to the state. No DynamoDB table. |
| Encryption | The bucket's default SSE-KMS with the account's tfstate key (`alias/sft/<env>/tfstate`) and S3 Bucket Keys. The backend sets no `encrypt` or `kms_key_id`: `encrypt = true` without a key asks S3 for SSE-S3 instead. The bucket policy refuses any other encryption. |
| Access | Only the plan role, the deploy role and the bootstrap admins may read or write objects; the bucket policy denies everyone else, BreakGlass included. The plan role writes and deletes only `.tflock` files and uses the key only to decrypt and generate data keys (ADR-0005). Versioning keeps every replaced state for 90 days, and the last ten of each always. |

Each root's backend block sets only `key`, `region` and `use_lockfile`. The bucket names the account, so it comes in
at init, and no bucket name or account ID is ever in the code:

```bash
terraform init -backend-config="bucket=sft-<env>-<region-short>-tfstate-${TF_VAR_account_id}"
```

`check.sh conventions` fails a root whose key isn't its directory, whose region isn't its Region, or whose backend
sets anything else.

## Roles for CI

| Role | Trust (T-71) | May |
|---|---|---|
| `sft-<env>-terraform-plan` | `repo:codewithmuh/secure-file-transfer:pull_request` only | Read state and write lock files; describe Regions and AZs |
| `sft-<env>-terraform-deploy` | `repo:codewithmuh/secure-file-transfer:environment:<env>` only (`dev`, `staging`, `prod`, `shared`) | Read and write state; describe Regions and AZs |
| `sft-<env>-keyadmin` | The account's `BreakGlass` permission set role only | Get and put key policies, through the key policies that name it |

All three sit under the `/sft-bootstrap/` IAM path, which only `Admin` may change (ADR-0006, SCP 4). Both trusts pin
the audience and the exact subject with `StringEquals`; the module's variables reject wildcards. Each GitHub
environment must accept deployments from `main` only, which is set in the repository settings, not here. The
management account has a plan role only.

The plan and deploy roles' permissions beyond state are a **placeholder** in `modules/terraform-oidc-roles`: each
issue that builds a layer adds what that layer needs.

## Conventions

### Names

| Kind | Pattern | Example |
|---|---|---|
| Regional resource | `sft-<env>-<region-short>-<thing>` | `sft-prod-apne1-vpc` |
| Global resource (IAM role, CloudFront) | `sft-<env>-<thing>` | `sft-prod-api`, `sft-prod-keyadmin` |
| S3 bucket (globally unique) | `sft-<env>-<region-short>-<thing>-<account-id>` | `sft-dev-apne1-tfstate-<account-id>` |
| KMS alias | `alias/sft/<env>/<class>` | `alias/sft/prod/files` |
| Secret | `sft/<env>/<name>` | `sft/prod/db/master` |

`<env>` is `management`, `shared`, `dev`, `staging` or `prod`; `<region-short>` is `apne1` (Tokyo) or `apne3` (Osaka).
The account ID in bucket names stops anyone else claiming our names first. Mind the short limits: load balancer and
target group names allow 32 characters, and `sft-staging-apne3-` already uses 18. S3 allows 63, IAM roles 64. The
`conventions` module builds the prefixes; use its outputs rather than writing a name out.

### Tags

Every provider sets `default_tags` from the `conventions` module, so every resource that takes tags gets:

| Tag | Value | Why |
|---|---|---|
| `project` | `secure-file-transfer` | Tells our resources from anything else in the account |
| `environment` | `management`, `shared`, `dev`, `staging`, `prod` | Cost per environment (capacity 7.3), alarms, access conditions |
| `region` | The stack's home Region; providers for another Region override it | Finding the stack that owns a global resource |
| `stack` | The root's directory under `infra/` | Which code and which state own the resource |
| `component` | The layer by default; a module may override it per resource, for example `aurora` or `nat` | Cost lines matched with capacity section 5 (capacity 7.3) |
| `managed-by` | `terraform` | Anything without it was made by hand (T-76) |
| `repository` | `codewithmuh/secure-file-transfer` | Where the code lives |
| `retention` | `audit-archive`, on the retained stack only | The CI guard and the NFR-19 budget filter (encryption 8.4) |

Cost Explorer can use `environment`, `component` and `stack` once they are activated as cost allocation tags in the
management account (#55).

### Account IDs and variables

Every root takes `account_id` as a variable (`TF_VAR_account_id` locally, a GitHub environment variable in CI) and
passes it to the provider's `allowed_account_ids`, so a stack refuses to run against any other account. Account IDs,
bucket names and `.tfvars` files are never committed (`.gitignore`); `check.sh conventions` fails any 12-digit number
under `infra/`. An AWS-owned account that must appear in code, such as the regional registries that serve EKS add-ons
(ADR-0021), goes on a line marked `aws-owned-account`.

### Versions

- Terraform `~> 1.17.0` in every root (ADR-0005 needs at least 1.11 for S3 lock files and write-only arguments). The
  checks run 1.17.1 from the image pinned in `scripts/check.sh`.
- The AWS provider pinned exactly, `6.71.0`, in every root, with a committed `.terraform.lock.hcl` that holds hashes
  for `linux_amd64` (CI), `linux_arm64` (Docker on Apple silicon) and `darwin_arm64` (Macs). Dependabot proposes one
  pull request per provider release for every root, after a week's cooldown (T-68).
- Modules require `>= 6.0.0` and configure no providers: roots do, and pass aliases in.
- Tool images (Terraform, tflint, Trivy) are pinned by version and digest at the top of `scripts/check.sh`; the tflint
  AWS ruleset by version in `.tflint.hcl`.

## Checks

```bash
make infra-check   # what CI runs: conventions, fmt, validate, tflint, Trivy
make infra-fmt     # terraform fmt, rewriting files
```

Only Docker is needed: `scripts/check.sh` runs each tool from its pinned image, as your user, with no credentials, no
AWS configuration and none of your environment.

| Check | What it does |
|---|---|
| `conventions` | Each root's backend key is its directory, its region is its Region, it sets only `key`, `region` and `use_lockfile`, and its `stack` matches; no account IDs |
| `fmt` | `terraform fmt -check -recursive -diff` |
| `validate` | `terraform init -backend=false -lockfile=readonly` and `validate` for every root, so a missing or stale lock file fails too |
| `tflint` | Terraform's own rules (preset `all`) and the AWS ruleset, through every root and the modules they call |
| `trivy` | Trivy's misconfiguration scan, failing on any severity. Exceptions live in [`.trivyignore.yaml`](../.trivyignore.yaml), each with its paths, its reason and its threat-model reference |

CI runs the same script in [`.github/workflows/infra.yml`](../.github/workflows/infra.yml), job
`Terraform (fmt, validate, tflint, Trivy)`. The workflow runs on every pull request so the check can be required by
name; when nothing under `infra/` (or the workflow, or the Trivy exceptions) changed, it passes without running the
tools.

Later checks from ADR-0005 and the threat model build on this: custom Rego policies for OIDC trusts, wildcard IAM
actions and the retained stack's guards, and plans in CI once the roles exist.

## Add a stack or a module

A stack:

1. Copy the nearest sibling root in the same account and Region, lock file included.
2. Set the backend `key` and the conventions module's `stack` to the new directory, and `component` to its layer.
3. If its providers differ from the sibling's, write a new lock file: `infra/scripts/check.sh lock <directory>`.
4. Add it to the apply order above and run `make infra-check`.

A module: a directory under `modules/` with `main.tf`, `variables.tf`, `outputs.tf` and `versions.tf`, every variable
and output described, no provider blocks, and names and tags taken from the caller's `conventions` outputs. Tokyo and
Osaka call the same module with different inputs; a Region-specific branch inside a module needs a reason in a
comment.
