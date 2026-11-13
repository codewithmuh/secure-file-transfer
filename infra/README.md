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
  shared/                              registry, the web app's bundle store, DNS zone, log archive (shared account)
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
| `bootstrap/<account>/ap-northeast-1` | each | Tokyo | The state bucket and tfstate key for Tokyo; the GitHub OIDC provider; the Terraform plan and deploy roles; the key-admin role and the emergency user (none of the last three in the management account) | The maintainer, `Admin` permission set, local state first |
| `bootstrap/<account>/ap-northeast-3` | staging, prod | Osaka | The state bucket for Osaka and the Osaka replica of the tfstate key | The maintainer, `Admin` permission set, local state first; in a Tokyo outage, the account's emergency user |
| `organization` | management | Tokyo (Organizations is global) | Organizations, OUs and accounts, Identity Center and permission sets, SCPs, budgets: [#55](https://github.com/codewithmuh/secure-file-transfer/issues/55); each environment's read-only role for the break-glass reconciliation (#239); the alert on SCP changes, in us-east-1 (#277) | The maintainer with MFA, never CI; CI plans it read-only (ADR-0006) |
| `shared` | shared | Tokyo, with Osaka and us-east-1 aliases when needed | ECR and the registry key, the web app's versioned bundle store and its publish role ([`modules/web-bundles`](modules/web-bundles/README.md), ADR-0008, #283), the public DNS zone, the organization's log archive | CI, `shared` environment |
| `environments/<env>/<region>/<layer>` | dev, staging, prod | dev: Tokyo; staging and prod: Tokyo and Osaka | Architecture 3.1 and 3.2, split into layers (below) | CI, the environment's GitHub environment |
| `environments/prod/retained` | prod | Tokyo, with an Osaka alias | The audit archive buckets and key in both Regions and what guards them after teardown (encryption 8.4) | CI, through its own deploy role; local state first |

| Layer | Holds | Notes |
|---|---|---|
| `network` | VPC, subnets, NAT gateways, VPC endpoints and their policies, the egress security groups, DNS Firewall, the flow log (ADR-0021) | [`modules/network`](modules/network/README.md); dev has two AZs, one NAT gateway and its endpoints in one AZ |
| `data` | Aurora, the files buckets, queues, the rate-limit store, the environment's KMS keys; the audit archive in dev and staging | In Osaka, the pilot light's replicas |
| `cluster` | EKS, the `system` node group, Karpenter's IAM, workload roles (ADR-0004) | [`modules/eks-cluster`](modules/eks-cluster/README.md); the account's IAM roles are made by the Tokyo stack, so Osaka's goes after it |
| `cluster-bootstrap` | Argo CD and its root Applications, Kyverno and its policies, Karpenter, External Secrets, the Load Balancer Controller, the egress proxy (ADR-0004, ADR-0005, ADR-0021); the observability stack's operator, namespaces and storage class, and its buckets and roles ([`modules/observability`](modules/observability/README.md), ADR-0009, #243) | [`modules/cluster-bootstrap`](modules/cluster-bootstrap/README.md); planned and applied only on `main`, by `.github/workflows/cluster-bootstrap.yml` through the Systems Manager tunnel (ADR-0021, #279), which applies the Prometheus Operator's CRDs first; pull request plans never reach a cluster API |
| `edge` | Load balancer, WAF, the environment's DNS records, the web bucket; in Tokyo, CloudFront and its us-east-1 certificate and web ACL, and the web app's release role (#283) | [`modules/edge`](modules/edge/README.md), [`modules/web-cdn`](modules/web-cdn/README.md) and [`modules/web-release`](modules/web-release/README.md); the API's target group, which the Load Balancer Controller fills by name from the chart's TargetGroupBinding (#106) |
| `identity` | SES (the `mail.<domain>` identity with DKIM and MAIL FROM, the configuration set `sft-<env>`, its SNS topic into the `ses-events` queue), the member user pool with its domain and app client and its sign-in triggers (#238), the `sft/<env>/app/*` secrets without values (ADR-0015, ADR-0016, encryption 6.4), and the probe mailbox: SES receiving for `probe.` (and `loadtest.` in staging) into the Region's mailbox bucket, with staging's load-test role (#259) | [`modules/ses`](modules/ses/README.md), [`modules/user-pool`](modules/user-pool/README.md), [`modules/signin-triggers`](modules/signin-triggers/README.md), [`modules/app-secrets`](modules/app-secrets/README.md), [`modules/probe-mailbox`](modules/probe-mailbox/README.md); after `data` and `edge`, before `cluster-bootstrap`, which reads its outputs (#185) |
| `alarms` | The AWS-side alarms and the watchdog (ADR-0009, A34): the Region's page, ticket and heartbeat topics, alarms on Aurora, the queues, S3 replication, the load balancer, the NAT gateways, KMS, SES and the sign-in triggers, the security alerts' EventBridge rules (#256), and in Tokyo the Route 53 health check alarms and the rule that forwards global sign-in events, in us-east-1 | [`modules/alarms`](modules/alarms/README.md); applied last in its Region, reading its `network`, `data` and `edge` states; Tokyo's in staging and prod after Osaka's `edge`. `TF_VAR_alert_emails` names who the alerts reach (#246) |
| `retained` | See above | prod only, one root for both Regions |

Every layer is written, and so are the `shared` stack and the bootstrap stacks.

Two deliberate exceptions to "one root per Region": `shared` and `retained` each hold a few Osaka (and us-east-1)
resources through provider aliases. Neither is in the failover path, and `retained` is one unit by design: its archive
and key outlive prod and keep their state in their own bucket (encryption 8.4).

### Modules

| Module | What it makes |
|---|---|
| `alarms` | One Region's alarm topics and CloudWatch alarms, with the watchdog's heartbeat alarm and, in Tokyo, the health check alarms and their key in us-east-1 ([README](modules/alarms/README.md), #246) |
| `app-secrets` | One Region's `sft/<env>/app/*` secrets, created without a value: the four keyrings in Tokyo, replicated to Osaka in staging and prod, and the Region's `idp-client` ([README](modules/app-secrets/README.md), #185) |
| `audit-archive` | One Region's audit archive bucket with Object Lock, its policy and replication to Osaka; in prod, called by the retained stack with its own replication role ([README](modules/audit-archive/README.md), #102) |
| `break-glass-role` | `sft-<env>-break-glass-db`, which only BreakGlass may assume, with a grant's session tag, to sign in to the database as `sft_breakglass` under an approved grant; the EventBridge rule and topic that page on every assumption ([README](modules/break-glass-role/README.md), #232) |
| `cluster-bootstrap` | The cluster's platform: Argo CD, Kyverno and its policies, Karpenter, External Secrets, the Load Balancer Controller, the egress proxy, operator RBAC, the Prometheus Operator ([README](modules/cluster-bootstrap/README.md), #104, #243) |
| `conventions` | Nothing: names, tags, the state bucket name and the bootstrap role names and ARNs, from the environment, Region and stack; the one definition of the Regions' short names and of the workload roles (#172). Every root calls it once and passes it to the modules that name things. |
| `ses` | One Region's SES setup: the domain identity with Easy DKIM, the Region's MAIL FROM subdomain, SPF and DMARC, the configuration set and its events through SNS into the `ses-events` queue, the identity policy for Cognito ([README](modules/ses/README.md), #185) |
| `tfstate-backend` | A state bucket and its tfstate key (or, in Osaka, the key's replica) with the bucket and key policies below |
| `terraform-oidc-roles` | The GitHub OIDC provider, the plan role and the deploy role |
| `key-admin-role` | `sft-<env>-keyadmin`, which only BreakGlass may assume (encryption 4.4, rule 6) |
| `emergency-user` | `sft-<env>-emergency` under `/sft-emergency/`, the account's way in when Identity Center can't be reached (authn-authz 8.4) |
| `dns-zone` | The public zone `sft.<domain>` with DNSSEC and CAA, and each environment's narrow DNS roles ([README](modules/dns-zone/README.md), #105) |
| `edge` | One environment's edge in one Region: the API load balancer, its certificate and web ACL, the sign-in web ACL, the edge's log buckets, the web bundle bucket, the API records and the health check ([README](modules/edge/README.md), #105) |
| `eks-cluster` | One EKS cluster per account and Region: private API, control-plane logs, the `system` node group, Karpenter's IAM, queue and node pools, Pod Identity roles, access entries, the tunnel's session document ([README](modules/eks-cluster/README.md), #103) |
| `events-delivery-role` | `sft-<env>-events-delivery`, the role every EventBridge rule delivers into our queues and topics through (encryption 4.4, #102) |
| `files-buckets` | One Region's files and large-files buckets: policies, lifecycle safety nets, replication with RTC from Tokyo, GuardDuty Malware Protection on large files and its results rule ([README](modules/files-buckets/README.md), #102) |
| `key-policy` | Nothing: the common part of a key policy for a key a deploy role creates ([README](modules/key-policy/README.md), #105) |
| `kms-keys` | The environment's keys, one per data class: primaries in Tokyo, replicas in Osaka, with the key policies of encryption 4.4 ([README](modules/kms-keys/README.md), #102) |
| `log-archive` | The organization's log archive under Object Lock, its logs key and the organization trail with the state buckets' data events ([README](modules/log-archive/README.md), #105) |
| `network` | One VPC per account and Region: subnets, NAT gateways, endpoints with organization-scoped policies, security groups, DNS Firewall, flow log ([README](modules/network/README.md), #56) |
| `probe-mailbox` | One Region's mailbox for the synthetic probe and the load test: the bucket (SSE-KMS, a 1-day expiry), SES receiving with its identity, rule set and rules, the MX records from Tokyo's stack, and in staging the load test's OIDC role and secret ([README](modules/probe-mailbox/README.md), #259) |
| `observability` | One cluster's observability buckets and roles: Loki's and Tempo's buckets under the logs key, the account's Loki, Tempo, Alertmanager and CloudWatch exporter roles (from Tokyo) and their Pod Identity associations ([README](modules/observability/README.md), #243) |
| `aurora` | One Region's Aurora PostgreSQL cluster: standalone (dev), the global database's primary (Tokyo) or secondary (Osaka), its security group and parameters, and the master secret ([README](modules/aurora/README.md), #101) |
| `data-stack` | One environment and Region's data layer: calls `aurora`, `valkey` and `queues` with the network stack's subnets and groups, so every `data` root passes only what differs (#101) |
| `queues` | Every SQS queue of ADR-0013 and its dead-letter queue, with a queue policy that admits only its one sender ([README](modules/queues/README.md), #101) |
| `signin-triggers` | One Region's Cognito sign-in triggers: the function (the API image), its role `sft-<env>-signin-trigger` (made in Tokyo), its security group and log group, and the user pool's permission to invoke it ([README](modules/signin-triggers/README.md), #238) |
| `registry` | ECR repositories, the registry key, the cross-account pull policy, the lifecycle rules, the push role and Osaka replication ([README](modules/registry/README.md), #105) |
| `user-pool` | One Region's member user pool: Plus tier with threat protection, MFA, admin-only sign-up, managed login on a Cognito prefix domain, the API's app client, the sign-in web ACL ([README](modules/user-pool/README.md), #185) |
| `valkey` | One Region's counter store: ElastiCache Serverless for Valkey, its IAM-authenticated users and security group ([README](modules/valkey/README.md), #101) |
| `web-bundles` | The web app's versioned bundle store in the shared account and its publish role, which only the registry environment may assume ([README](modules/web-bundles/README.md), ADR-0008, #283) |
| `web-cdn` | The CloudFront distribution for the web bundle, with Osaka failover, its us-east-1 certificate and web ACL, its logs and the app record ([README](modules/web-cdn/README.md), #105) |
| `web-release` | `sft-<env>-web-release`, the web app's release role: reads the bundle store, writes the environment's web buckets, from the GitHub environment `web-<env>` only ([README](modules/web-release/README.md), #283) |

## Apply order

Before any of it, the GitHub environments `dev`, `staging`, `prod`, `shared` and `registry` (the image push role's,
ADR-0007), each accepting deployments from `main` only, so that no deploy role ever exists without the rule its trust relies on (the runbook's step 0, T-71).

1. `bootstrap/management/ap-northeast-1`, before anything else exists.
2. `organization`: the budgets first, then the organization, OUs and member accounts, the SCPs, and, once Identity
   Center is enabled in the console, the permission sets and groups. Two console steps and a few flags make it more
   than one apply: follow [the runbook](../docs/runbooks/organization-and-bootstrap.md), which covers steps 1 to 3.
3. For each member account (shared, dev, staging, prod): `bootstrap/<account>/ap-northeast-1`, then the emergency
   user's password and security keys in the console, then, for staging and prod, `bootstrap/<account>/ap-northeast-3`,
   which needs the Tokyo stack's `tfstate_key_arn` output and its roles.
4. `shared`.
5. For each environment, in Tokyo and then in Osaka: `network`, `data`, `cluster`, `edge`, `identity`,
   `cluster-bootstrap`, then `alarms` once both Regions' `edge` exist (Tokyo's reads Osaka's health check). In prod,
   `retained` goes before `data`, because the environment refers to the archive by ARN; it needs
   `TF_VAR_alert_emails` for its own alert topics, and the GitHub environment `prod-retained` (main only) that its
   deploy role trusts. Every `network` root needs `TF_VAR_domain`: DNS Firewall answers the API's and the web app's
   names, which the synthetic probe calls (#259). Staging's load test needs the GitHub environment `loadtest-staging`
   (main only) that its role trusts. On a fresh build `network`
   runs twice: first without a flow log, then, once `data` has made the log bucket, with
   `TF_VAR_flow_log_destination_arn` set to it, because the flow log can't exist before its bucket (capacity A19).
   In staging and prod `data` also runs twice in Tokyo, because the two Regions need each other's keys and buckets:
   Osaka's `data` replicates Tokyo's key primaries (`TF_VAR_primary_key_arns`, from Tokyo's `kms_key_arns` output),
   while Tokyo's bucket replication and the master secret's Osaka replica need Osaka's buckets and key replicas. So
   Tokyo first with `TF_VAR_osaka_ready=false`, then Osaka, then Tokyo again without it (`osaka_ready` defaults to
   true; modules/files-buckets, modules/data-stack).
   Tokyo's `data` also makes the Auto Scaling and EC2 Fleet service-linked roles before the keys whose policies name
   them; in an account that already has either, import it first
   (`terraform import 'module.data.aws_iam_service_linked_role.volumes["autoscaling"]' <role ARN>`).
   Tokyo's `cluster` makes the account's IAM roles and Osaka's refers to them, so Osaka's goes after it; both need
   `data` first, for the keys' aliases and EventBridge's delivery role. `cluster-bootstrap` reaches the cluster API
   only through the Systems Manager tunnel, as the deploy role, in CI's `cluster-bootstrap` workflow (#279), which
   server-side applies the Prometheus Operator's CRDs before each apply (modules/cluster-bootstrap). It needs
   `TF_VAR_domain` for the application's names, and reads the user pool, its login domain, its app client and the SES
   configuration set from the Region's `identity` state; Tokyo's in staging and prod also reads Osaka's (the key
   rotation job rotates Osaka's client too, and the operator API's drift check reads both pools), so both Regions'
   `identity` go before Tokyo's `cluster-bootstrap`. `TF_VAR_break_glass_reconciliation`, from the organization stack's
   outputs, switches on the operator API's break-glass reconciliation (#275).
   `identity` needs `data` (the `ses-events` queue, Osaka's secrets key) and `edge` (the sign-in web ACL), and
   `TF_VAR_shared_account_id`, `TF_VAR_domain`, `TF_VAR_dmarc_report_address` and, in an apply job,
   `TF_VAR_terraform_role=deploy`. Its secrets have no value until the key rotation job's first run, so after the first
   sync start that job by hand before the API can start (deploy/README.md). SES production access is requested per
   Region in the console (ADR-0015).
   `edge` needs nothing from the cluster stacks: the Load Balancer Controller finds the API's target group by name
   (`sft-<env>-<region-short>-api`), so its pods register whenever both exist. In staging and prod, Osaka's `edge`
   runs after Tokyo's, with `TF_VAR_web_distribution_arn` set to Tokyo's `web_distribution_arn` output: the Osaka web
   bucket's only reader is that distribution. The edge roots need `TF_VAR_shared_account_id` and `TF_VAR_domain`, and
   `TF_VAR_terraform_role=deploy` in an apply job.

Teardown runs the other way. Each `data` stack first gets an apply with `TF_VAR_teardown=true`, which turns Aurora's
deletion protection off, skips the final snapshot, drops the master secret's recovery window and lets the files
buckets be emptied (prod's too, from that apply on, #263), then the destroy. Prod's `cluster`, `identity` and `edge`
take the same input for their deletion protection.
Prod's `retained` stack stays, and a bootstrap stack goes only when its environment is
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
printf 'terraform {\n  backend "local" {}\n}\n' > backend_override.tf   # git-ignored; check.sh fails while it exists
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
| Access | Only the plan role, the deploy role and the bootstrap admins may read or write objects, and only the bootstrap admins may change the bucket: its policy, versioning, lifecycle rules, default encryption, replication, inventory, Object Lock, ownership and public access settings, or delete it. The bucket policy denies both to everyone else, BreakGlass included, and SCP 3 repeats the second in the member accounts. The plan role writes and deletes only `.tflock` files and uses the key only to decrypt and generate data keys (ADR-0005). Versioning keeps every replaced state for 90 days, and the last ten of each always. |
| Bootstrap admins | The `Admin` permission set; in the management account, whatever `TF_VAR_admin_principal_arn_patterns` names. In Osaka, also the account's emergency user, `sft-<env>-emergency`, by its exact ARN: a Tokyo outage takes Identity Center and so `Admin` with it (ADR-0006, authn-authz 8.4). |

Each root's backend block sets only `key`, `region` and `use_lockfile`. The bucket names the account, so it comes in
at init, and no bucket name or account ID is ever in the code:

```bash
terraform init -backend-config="bucket=sft-<env>-<region-short>-tfstate-${TF_VAR_account_id}"
```

`check.sh conventions` fails a root whose key isn't its directory, whose region isn't its Region, or whose backend
sets anything else, and any `override.tf`, `*_override.tf` or their `.tf.json` forms anywhere under `infra/`,
committed or not, because an override file replaces a backend without showing in the file it changes. The
bootstrap's `backend_override.tf` is the one override ever used, and it is gone before the state moves.

## Roles for CI

| Role | Trust (T-71) | May |
|---|---|---|
| `sft-<env>-terraform-plan` | `repo:codewithmuh/secure-file-transfer:pull_request` only | Read state and write lock files; describe Regions and AZs; in dev, staging and prod, read the network, data, storage, cluster, edge, identity and alarms layers; in shared, the shared stack (below) |
| `sft-<env>-terraform-deploy` | `repo:codewithmuh/secure-file-transfer:environment:<env>` only (`dev`, `staging`, `prod`, `shared`) | Read and write state; describe Regions and AZs; in dev, staging and prod, build the network, data, storage, cluster, edge, identity and alarms layers; in shared, the shared stack (below) |
| `sft-<env>-keyadmin` | The account's `BreakGlass` permission set role only | Get and put key policies, through the key policies that name it |

All three sit under the `/sft-bootstrap/` IAM path, which only `Admin` may change (ADR-0006, SCP 4). So does the
retained stack's own deploy role, which must be named `sft-prod-retained-terraform-deploy`: the SCPs treat every
`sft-*-terraform-deploy` under that path as a deploy role, and SCP 5 names this one. Both trusts pin
the audience and the exact subject with `StringEquals`; the module's variables reject wildcards. Each GitHub
environment must accept deployments from `main` only, which is set in the repository settings, not here: the
bootstrap runbook creates all four with that rule in its step 0, before any deploy role exists, because GitHub
creates an environment with no rules the first time a job names it. The management account has a plan role only.

Each member account also has an **emergency IAM user**, `sft-<env>-emergency` under `/sft-emergency/`, made by its
Tokyo bootstrap stack with `AdministratorAccess` and bound by the SCPs like everyone else. It is for when Identity
Center can't be reached (authn-authz 8.4). The maintainer gives it a console password kept offline and a security
key in the console, so neither is ever in state; it never has access keys. In staging and prod, Osaka's state bucket
and tfstate key name it as a bootstrap admin, and SCPs 2 and 3 let it through for them, so Osaka's bootstrap stack
can still be applied in a Tokyo outage. Only `Admin` may create or change IAM users, their passwords and their MFA
devices (SCP 4).

The plan and deploy roles' permissions beyond state are a **placeholder** in `modules/terraform-oidc-roles`: each
issue that builds a layer adds what that layer needs. The management account's plan role is the first to have real
ones: read access to Organizations, Identity Center, Budgets and the cost allocation tags, for read-only plans of the
organization stack, passed in as `plan_policy_json`.

## Organization and guardrails

`organization` holds everything that binds the accounts from above ([ADR-0006](../docs/adr/0006-aws-account-per-environment.md)).
SCPs never bind the management account, so it holds nothing else and is applied only by the maintainer with MFA. The
one alert it holds watches the SCPs themselves: `sft-management-scp-changed`, an EventBridge rule in us-east-1, where
Organizations records its calls, on any attach, detach, update or delete of a policy and any change of a policy type,
into the topic `sft-management-scp-alerts` that `TF_VAR_alert_emails` subscribe to (scp-alerts.tf, #277,
docs/runbooks/scp-change.md).

| | |
|---|---|
| OUs and accounts | `prod` (prod), `nonprod` (dev, staging), `shared` (shared). Accounts are named `sft-<env>`; their emails come in as `TF_VAR_account_emails`. `prevent_destroy` and `close_on_deletion = false`: nothing here closes an account. |
| Root access | Centralized root access: member accounts have no root credentials. A privileged root task runs from the management account through `sts:AssumeRoot`. |
| Trusted access | Identity Center, IAM (root access) and CloudTrail. The shared account is CloudTrail's delegated administrator: the shared stack creates the organization trail next to its log archive, and that trail must log S3 data events on every `sft-*-tfstate-*` bucket (`.trivyignore.yaml`). GuardDuty and Config belong to each environment, so neither is delegated. |
| Budgets | $6,500 in total and per account: shared $20, dev $500, staging $800, prod $5,180 (capacity 7.3). Alarms by email at 50 % actual, 80 % and 100 % actual and forecast (NFR-20). The $7 NFR-19 budget is the retained stack's. |
| Cost allocation tags | `environment`, `component`, `stack` |

**SCPs.** Deny statements only; `FullAWSAccess` stays the allow. "Apply roles" are the deploy roles
(`/sft-bootstrap/sft-*-terraform-deploy`, the retained stack's included) and the `Admin` permission set.

| SCP | Attached to | Denies |
|---|---|---|
| 1 `region-guard` | Root | Everything outside Tokyo and Osaka, except global services (IAM, STS, Route 53, CloudFront, Organizations, account, billing, Budgets, Cost Explorer, Support, Health) and, in us-east-1 only, ACM, WAF, CloudWatch, SNS, CloudWatch Logs delivery, KMS and EventBridge, whose rule there forwards root, IAM user and global STS events to Japan for the security alerts (NFR-21, #256). Also log groups in us-east-1, KMS replicas outside Osaka, and VPC endpoints to services outside Japan; `vpce:AllowMultiRegion` passes (ADR-0021). |
| 2 `keys` | Root | Disabling or deleting KMS keys, or deleting imported key material, to all but apply roles and the staging and prod emergency users; putting key policies to all but those and `sft-<env>-keyadmin`. The key policies keep the emergency users to Osaka's tfstate keys. |
| 3 `accounts-and-logging` | Root | Leaving the organization; the root user's own credentials; sharing EBS or RDS snapshots; turning off account-wide S3 Block Public Access or EBS default encryption, and changing CloudTrail, Config, GuardDuty, EKS logging, `sft-*` EventBridge rules and alarms or `/aws/eks/*` log groups, to all but apply roles; changing the settings of a `sft-*-apne?-tfstate-*` state bucket or deleting it, to all but `Admin`, the staging and prod emergency users and assumed-root sessions (#81) |
| 4 `iam` | Root | Changing roles, policies and OIDC or SAML providers to all but deploy roles; changing what is under `/sft-bootstrap/`, the GitHub OIDC provider and `OrganizationAccountAccessRole` to all but `Admin`; access keys and service-specific credentials to everyone; creating, renaming, deleting IAM users or changing their passwords, policies or MFA devices to all but `Admin` |
| 5 `audit-archive` | `prod` OU | Changing the policy, lifecycle, Object Lock, replication, versioning, encryption or public access settings of `sft-prod-apne?-audit-archive-*` and `sft-prod-apne?-retained-*` buckets to all but the retained stack's deploy role and `Admin` |

**Permission sets.** Group assignments only; nobody holds `Admin` or `BreakGlass` standing.

| Permission set | Session | Policies | Assigned |
|---|---|---|---|
| `Admin` | 1 hour | `AdministratorAccess` | By a `BreakGlassApprover`, one person, at most an hour, any account |
| `BreakGlass` | 1 hour | `AdministratorAccess`, bound by the SCPs and the bucket and key policies | By a `BreakGlassApprover`, one person, at most an hour |
| `BreakGlassApprover` | 1 hour | Create and delete assignments of `Admin` and `BreakGlass`; read people and assignments | `sft-breakglass-approvers`, management account |
| `ReadOnly` | 4 hours | `ViewOnlyAccess`, `CloudWatchReadOnlyAccess`, EKS describe | `sft-readonly`, every member account |
| `Operator` | 2 hours | `ReadOnly`'s, plus SSO providers in the user pools | `sft-operators`, dev, staging, prod |
| `AuditReader` | 1 hour | Read `sft-*-audit-archive-*` and `sft-shared-*-log-archive-*`, decrypt through S3 | `sft-audit-readers`, every member account |

Still to add here, by the issues that bring what they need: Systems Manager port forwarding for `ReadOnly` and
`Operator` (cluster layer), the failover steps for `Operator` (M7), and the break-glass tool's EventBridge Scheduler
removal and alerts (FR-35, M6).

## Conventions

### Names

| Kind | Pattern | Example |
|---|---|---|
| Regional resource | `sft-<env>-<region-short>-<thing>` | `sft-prod-apne1-vpc` |
| Global resource (IAM role, CloudFront) | `sft-<env>-<thing>` | `sft-prod-api`, `sft-prod-keyadmin` |
| S3 bucket (globally unique) | `sft-<env>-<region-short>-<thing>-<account-id>` | `sft-dev-apne1-tfstate-<account-id>` |
| Names the SCPs and permission sets rely on | Audit archive `sft-<env>-<region-short>-audit-archive-<account-id>`; the retained stack's other buckets `sft-prod-apne1-retained-<thing>-<account-id>`; the log archive `sft-shared-apne1-log-archive-<account-id>`; alert rules and alarms `sft-*` | `sft-prod-apne3-audit-archive-<account-id>` |
| KMS alias | `alias/sft/<env>/<class>` | `alias/sft/prod/files` |
| Secret | `sft/<env>/<name>` | `sft/prod/db/master` |

`<env>` is `management`, `shared`, `dev`, `staging` or `prod`; `<region-short>` is `apne1` (Tokyo) or `apne3` (Osaka),
from the conventions module's `region_shorts`, the one definition every module reads (#172). The environment's
workload roles, `sft-<env>-<name>` at path `/`, are listed once too, by the layer that makes each
(`workload_roles`): key, bucket and queue policies, the cluster layer and the deploy role's permissions all read that
list, so a renamed or new role can't be missed in one copy.
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

The organization stack activates `environment`, `component` and `stack` as cost allocation tags in the management
account, so Cost Explorer can split cost by them (capacity 7.3).

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
make infra-check   # what CI runs: conventions, fmt, validate, tflint, Trivy, terraform test
make infra-fmt     # terraform fmt, rewriting files
```

Only Docker is needed: `scripts/check.sh` runs each tool from its pinned image, as your user, with no credentials, no
AWS configuration and none of your environment.

| Check | What it does |
|---|---|
| `conventions` | Each root's backend key is its directory, its region is its Region, it sets only `key`, `region` and `use_lockfile`, and its `stack` matches; no Terraform override files under `infra/`; no account IDs |
| `fmt` | `terraform fmt -check -recursive -diff` |
| `validate` | `terraform init -backend=false -lockfile=readonly` and `validate` for every root, so a missing or stale lock file fails too |
| `tflint` | Terraform's own rules (preset `all`) and the AWS ruleset, through every root and the modules they call |
| `trivy` | Trivy's misconfiguration scan, failing on any severity. Exceptions live in [`.trivyignore.yaml`](../.trivyignore.yaml), each with its paths, its reason and its threat-model reference |
| `test` | `terraform test` for every module with a `tests/` folder, planning it against a mocked AWS provider, so nothing reaches AWS. The edge and web-cdn modules check every WAF rule and its logging this way (#235, abuse 9.2). A module has no lock file, so the dev edge root's pins the provider for the run |

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

## Layer permissions

- **Network** (#56), in the Regions of the bootstrap root's `network_regions` (dev: Tokyo; staging and prod: both).
  The plan role reads: EC2's network Describe calls, DNS Firewall's Get and List calls, and
  `organizations:DescribeOrganization` for the endpoint policies' organization ID. The deploy role also creates and
  changes VPC resources of the types the module uses in its own account, endpoints only for AWS services
  (`ec2:VpceServiceOwner`), deletes only resources tagged `managed-by = terraform` and `project =
  secure-file-transfer`, delivers flow logs (`logs:CreateLogDelivery`), writes DNS Firewall but no other Resolver
  resource, and, where it has two Regions, holds `vpce:AllowMultiRegion` for the cross-Region S3 endpoint.
- **Data, stores** (#101), in the same Regions (`permissions-data.tf`), as managed policies `sft-<env>-terraform-plan-data`
  and `sft-<env>-terraform-deploy-data` under `/sft-bootstrap/`. The plan role reads: RDS, ElastiCache and log group
  Describe calls, the queues' attributes, the master secret's metadata and version list, never its value, and
  `secretsmanager:GetRandomPassword`, because the master password's ephemeral resource opens during plans too. The
  deploy role also creates and changes `sft-*` clusters, instances, global clusters, subnet and parameter groups,
  serverless caches, users and user groups, queues, the `sft/*/db/*` secrets and the `/aws/rds/cluster/sft-*` log
  groups (including `ResetDBClusterParameterGroup`, which the provider calls when a parameter is removed); deletes only
  those tagged `managed-by = terraform` and `project = secure-file-transfer`, except the final snapshot
  `sft-*-aurora-final`, which a delete creates untagged and so is allowed by name; reads the master secret's value
  (`sft/*/db/master-*` only) for the read-back that sets the cluster's password at apply (modules/aurora); creates the
  RDS and ElastiCache service-linked roles; and uses KMS keys only through RDS, ElastiCache, Secrets Manager and SQS
  (`kms:ViaService`), with grants for AWS resources only, and `Encrypt` for the master secret's Osaka replica. Its
  security groups use the network layer's EC2 permissions.

- **Storage and keys** (#102), in the same Regions, as managed policies under `/sft-bootstrap/`
  (`sft-<env>-terraform-storage-read`, `-kms` and `-write`, in `modules/terraform-oidc-roles/permissions-storage.tf`).
  The plan role reads keys, the files and archive buckets' settings, the storage roles, GuardDuty plans and `sft-<env>-*`
  rules. The deploy role also creates multi-Region keys and administers them (each key policy then limits it),
  replicates only to Osaka, creates grants only for AWS resources through RDS, ElastiCache and EKS, encrypts the
  secrets it writes, manages the buckets `sft-<env>-apne?-{files,large-files,audit-archive}-<account-id>` (not the
  archive in prod, which is the retained stack's), the roles `sft-<env>-{s3-replication,s3-batch-replication,malware-protection,events-delivery}`
  (the conventions module's data layer list) and the services they are passed to (`events-delivery` only with the workload boundary), the Auto Scaling and EC2
  Fleet service-linked roles that the platform and files keys name, the account's EBS encryption by default,
  GuardDuty plans and `sft-<env>-*` rules, in our Regions and us-east-1 (the alarms layer's forwarding rule, #256). In
  dev and staging it may empty the buckets at teardown.

- **Cluster** (#103), in the same Regions: every environment Region with a network has a cluster. Three managed
  policies under `/sft-bootstrap/` (`sft-<env>-terraform-cluster-read`, `-cluster-deploy`, `-cluster-deploy-iam`),
  not inline ones, and the workload permissions boundary `sft-<env>-workload-boundary`. The plan role reads EKS, the
  launch templates, the interruption queue and rules, the log groups, the tunnel document, IAM roles (Identity
  Center's included) and KMS aliases. The deploy role also builds EKS resources named `sft-<env>-*`, never with a
  public endpoint (`eks:endpointPublicAccess`), the system nodes' launch templates, the queue, rules, log groups and
  document; it creates and changes only the cluster layer's named roles, only with the boundary, never assumes them,
  attaches only four AWS managed policies, and passes roles only to EKS, Pod Identity, EC2 and, for the data layer's
  execution role, EventBridge ([`modules/eks-cluster`](modules/eks-cluster/README.md#roles)).
- **Cluster bootstrap** (#104), in the same Regions, deploy role only, as `sft-<env>-terraform-cluster-bootstrap`
  (`permissions-cluster-bootstrap.tf`): finding the system nodes, and starting a Systems Manager session only with the
  cluster's tunnel document and only on instances tagged `eks:nodegroup-name = sft-<env>-<rs>-system`, with the
  document check on; ending or resuming only its own sessions. The cluster API admits it through the cluster layer's
  access entry. The plan role gets nothing: the layer is planned only on `main`.
- **Edge** (#105), in the same Regions, plus us-east-1 for CloudFront's certificate, web ACL and log delivery. Managed
  policies `sft-<env>-terraform-edge-read` and `-write` under `/sft-bootstrap/`
  (`modules/terraform-oidc-roles/permissions-edge.tf`): load balancers, ACM, WAF, CloudFront, Route 53 health checks,
  CloudWatch Logs delivery and the edge's own buckets; deletes of load balancer resources only when tagged
  `managed-by = terraform`. The plan role may assume `sft-shared-dns-<env>-plan` in the shared account, the deploy role
  `sft-shared-dns-<env>-deploy` (bootstrap input `shared_account_id`).
- **Identity** (#185), in the same Regions (`permissions-identity.tf`): `sft-<env>-terraform-identity-read` for the
  plan role (SES, the `ses-events` topics, the pools, their domains and clients, the sign-in web ACL association, the
  `sft/<env>/app/*` secrets' metadata) and one policy for the deploy role, `-identity`, which holds the same reads and
  also builds SES identities and configuration sets, the `sft-<env>-<rs>-ses-events` topics, user pools with their
  domain, client and branding (never a user), and the app secrets without a value (no `PutSecretValue` or
  `GetSecretValue`: only the key rotation job writes them). DNS goes through the environment's DNS roles, as the edge's.
- **Break-glass database role** (#232), in the same Regions (`permissions-break-glass.tf`):
  `sft-<env>-terraform-break-glass-read` for the plan role and `-break-glass` for the deploy role, which also creates,
  changes and deletes the role `sft-<env>-break-glass-db` and its inline policies (never passed, no boundary) and the
  `sft-<env>-<rs>-break-glass-alerts` topics. Its rule is an `sft-<env>-*` rule, under the storage policies.
- **Alarms** (#246), in the same Regions plus us-east-1 (`permissions-alarms.tf`): `sft-<env>-terraform-alarms-read`
  for the plan role and `-alarms` for the deploy role, which also creates, changes and deletes `sft-<env>-*` alarms, the
  alarm topics and their subscriptions (the break-glass topics' included), and creates the us-east-1 key and its alias,
  which the key's own policy then gives the deploy role to administer. The plan role may also read CloudWatch metrics
  in Tokyo, so the promotion gate can read the synthetic probe's result as the previous environment's plan role
  (`.github/workflows/promote.yml`, #247).
- **Probe mailbox** (#259), in the same Regions (`permissions-mailbox.tf`): `sft-<env>-terraform-mailbox-read` for the
  plan role and `-mailbox` for the deploy role: the mailbox buckets `sft-<env>-apne?-probe-mailbox-<account-id>`,
  SES's receipt rule sets and rules, and staging's load-test role `sft-<env>-loadtest` and its secret
  `sft/<env>/loadtest/*`, never its value. Its own policies, because the identity layer's is near IAM's limit.
- **Shared** (#105), in the shared account (`shared_stack = true`): managed policies `sft-shared-terraform-shared-read`
  and `-write` (`permissions-shared.tf`) for ECR in Tokyo and Osaka, creating KMS keys and aliases (each key's own
  policy then makes the deploy role its administrator), the zone and DNSSEC, IAM roles under `/sft-shared/` only, the
  log archive bucket and the organization trail.

**IAM quotas.** With the identity layer, an environment's deploy role has 11 managed policies (data 1, storage 3,
cluster 3, cluster bootstrap 1, edge 2, identity 1), one over IAM's default limit of 10 per role, and its plan role 5.
The break-glass database role (#232) adds one to each: 12 and 6. The observability stack (#243) adds one to the
deploy role, and the boundary its roles carry, which is attached to none; the alarms layer (#246) adds one more to each:
14 and 7; the probe mailbox (#259) one more again: 15 and 8.
So before the bootstrap apply that adds the identity layer's policies, raise each environment account's quota in
Service Quotas: IAM, "Managed policies per role" (`L-0DA4ABF3`), to 20, in us-east-1, where IAM's global quotas live
(`aws service-quotas request-service-quota-increase --service-code iam --quota-code L-0DA4ABF3 --desired-value 20
--region us-east-1`, with the account's named profile). Merging was the other way, and doesn't fit: the edge's two
come to about 7,000 characters together, and the identity layer's deploy policy, which already folds in its reads, to
about 5,300. Until the quota is raised, that bootstrap apply fails at the attachment. Each managed policy must stay
under IAM's 6,144 characters; counted from their statements, the edge's two come to about 2,000 and 5,000 in staging
and prod. No static check measures the rendered JSON, so the bootstrap apply is the test.

These policies change only through an **Admin apply of each account's Tokyo bootstrap stack** (SCP 4 keeps
`/sft-bootstrap/` with `Admin`), never through CI. So before an environment's first network plan in M4, apply
`bootstrap/<env>/ap-northeast-1` again with the `Admin` permission set. The roles' inline policies share IAM's limit
of 10,240 characters per role, so later layers use managed policies under `/sft-bootstrap/` instead, which SCP 4
already keeps with `Admin` (its `bootstrap_iam_resources`).
