# 0006. Use one AWS account per environment under AWS Organizations

- Status: accepted
- Date: 2026-11-03
- Issue: [#31](https://github.com/codewithmuh/secure-file-transfer/issues/31)

## Context

PRD open question 4 asks whether dev, staging and prod share one AWS account. The answer shapes every IAM policy, the
pipeline's roles and what survives teardown:

- **Guards that bind administrators.** The key-policy guard (decision 13 in
  [encryption](../security/encryption-and-keys.md) 4.4), the region guard of NFR-21 and the protection of CloudTrail,
  Config and GuardDuty ([threat model](../threat-model.md) T-61, T-74, T-75) must hold against an account's own
  administrators and `BreakGlass`. Only service control policies do that, and they need AWS Organizations, which IAM
  Identity Center needs too ([authn-authz](../security/authn-authz.md) 8.1).
- **Teardown.** Each environment is destroyed on its own; the prod audit archive and its key outlive prod "in an AWS
  account that stays open" (NFR-19, encryption 8.4); the registry outlives every environment
  ([capacity](../design/capacity-and-cost.md) 5.4).
- **Stepping stones.** dev and staging hold no customer data but share the pipeline and the people, so they can lead
  to prod (threat model 1.1).
- **Cost control.** A budget per account is the planned rule (capacity 7.3, NFR-20).
- **Constraints.** One maintainer, whose personal AWS account is the starting point. Nothing is applied until the
  maintainer names the CLI profiles, and the default CLI identity is never used.

## Decision

Use **AWS Organizations**, with the maintainer's personal account as the **management account**, holding no
workloads. Create four member accounts: **dev**, **staging**, **prod**, and **shared** for the container registry
([ADR-0007](0007-container-registry-ecr.md)), the web bundle artifacts ([ADR-0008](0008-web-app-s3-cloudfront.md)), the
public DNS zone ([ADR-0021](0021-network-design-and-egress.md)) and the organization's log archive. Group them in
three OUs: `prod`, `nonprod` (dev, staging) and `shared`. People sign in through **IAM Identity Center**, home Region
Tokyo, with MFA by security key or passkey. **SCPs** carry the region guard and the key, logging, IAM and archive
protections. The retained stack stays in the prod account, which stays open after teardown.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **One account per environment, plus shared, under Organizations** (chosen) | A leaked dev or staging credential can't reach prod. SCPs bind every principal in a member account, `BreakGlass` and the account's own administrators included. Each environment tears down inside its own account; the registry outlives them in shared. Bills, budgets and service quotas (SES sending, EKS, EC2) separate by account, without relying on tags. | Cross-account wiring: image pulls from shared, the web bundle copy, DNS records, log delivery, and state buckets and OIDC roles in every account. Five accounts to secure (root MFA, emergency users, GuardDuty, Config, budgets). SCPs don't apply to the management account, so it must stay empty and its sign-in is the most valuable. A closed account takes 90 days to be fully removed. |
| **One account for everything** | Least setup; no cross-account access; one bill. | dev, staging and prod share IAM, quotas and blast radius; isolation rests on tags and IAM conditions written perfectly; environment teardown runs in the account that holds prod; a separate operator permission set per environment is needed just to tell them apart (authn-authz 8.2); budgets only by tag. |
| **A full landing zone** (AWS Control Tower, with separate log archive, security tooling and audit-archive accounts) | What large companies run: managed guardrails, separate accounts for logs and security tools, account vending. | Control Tower's own trails, Config recorders and baseline stacks add resources in every governed account and Region, which complicates the NFR-19 teardown and its $7 cap. Seven or more accounts for one maintainer. An audit-archive account would put cross-account writes on the request path, because the API writes security-critical records straight to the archive (architecture 4.2, 4.4). |

## Consequences

- **The management account** holds Organizations, Identity Center, the SCPs, consolidated billing and the overall
  $6,500 budget, nothing else. Its organization stack is applied by the maintainer with MFA, not from CI, because no
  SCP can limit a role in that account; CI only checks and plans it read-only.
- **Identity Center** permission sets: `ReadOnly`, `Operator`, `BreakGlassApprover` and `BreakGlass` (authn-authz 8.1),
  `AuditReader` (encryption 8.4), and `Admin`, used only for the bootstrap applies (ADR-0005). Like `BreakGlass`,
  nobody holds `Admin` standing: a `BreakGlassApprover` assigns it for at most one hour through the break-glass tool, a
  schedule removes the assignment, and every assignment, sign-in and call alerts (authn-authz 8.3). One CLI profile per
  account. If Tokyo is lost, Identity Center is too, and operators use the emergency IAM users of authn-authz 8.4.
- **SCPs**, attached to the organization root unless noted, grouped by purpose: the root holds `FullAWSAccess` and
  four. AWS allowed five per target and 5,120 characters each when this was written, and ten and 10,240 since May 2026,
  which leaves room. "Deploy roles" below are the Terraform apply roles and the retained stack's deploy role
  (`sft-prod-retained-terraform-deploy`, under `/sft-bootstrap/`). The organization stack (#55) holds them; infra/README
  has the full table.
  1. **Region guard (NFR-21).** Deny any request outside ap-northeast-1 and ap-northeast-3, except the global services
     NFR-21 exempts (IAM, Route 53, Budgets) and the account-level services that exist only globally (Organizations,
     account settings, billing and Cost Explorer, Support, Health). In us-east-1 alone it also allows what CloudFront
     and Route 53 need there, which NFR-21 lists: CloudFront, its WAF web ACL and its ACM certificate; CloudWatch
     metrics and alarms, and the SNS topic those alarms notify; CloudWatch Logs delivery for the CloudFront web ACL's
     logs, which land in S3 in Tokyo; the alarms on Route 53 health checks; and the KMS key that signs the zone for
     DNSSEC. None of them holds file contents. The guard doesn't block `vpce:AllowMultiRegion`, which the cross-region
     S3 endpoint needs (ADR-0021).
  2. **Keys (decision 13).** Deny `kms:PutKeyPolicy`, `kms:DisableKey`, `kms:ScheduleKeyDeletion` and
     `kms:DeleteImportedKeyMaterial` to every principal except the deploy roles, the bootstrap `Admin` role for the
     tfstate keys its stack creates, the staging and prod emergency users for Osaka's tfstate key (authn-authz 8.4,
     #81), and the `sft-{env}-keyadmin` role of
     [ADR-0017](0017-kms-keys-per-data-class.md), which `BreakGlass` uses only to recover a key policy and which may
     only put key policies.
  3. **Accounts and logging.** Deny leaving the organization, the root user in member accounts, turning off S3 Block
     Public Access or EBS default encryption, and sharing snapshots outside the organization. Deny stopping, changing or
     deleting CloudTrail, Config, GuardDuty, EKS control-plane logging and the alert rules to everyone but the deploy
     roles, and the bootstrap `Admin` role for what its stack creates, so an apply or a teardown can create and destroy
     them and nobody else can, `BreakGlass` included (T-60, T-74, T-75). EKS logging is set by
     `eks:UpdateClusterConfig`, which also sets endpoint access, so that call stays with the apply roles too. Deny
     changing a Terraform state bucket's policy, versioning, lifecycle, encryption, replication, inventory, Object
     Lock, ownership or public access settings, or deleting it, to everyone but `Admin`, the staging and prod
     emergency users and assumed-root sessions (T-73, #81); the state bucket policies repeat it.
  4. **IAM.** Deny creating, changing or deleting IAM roles, their trust and permission policies, and OIDC providers to
     everyone except the deploy roles, `BreakGlass` and `Admin` included. The roles the bootstrap applies create (the
     plan, apply and key-administration roles, the retained stack's deploy role and the OIDC provider, under the
     `/sft-bootstrap/` path) are the exception the other way: only `Admin` may change them, never a deploy role, so no
     deploy role can widen its own trust (T-71).
  5. **prod OU only.** Only the retained stack's deploy role may change the archive buckets' policies, lifecycle rules
     and Object Lock settings (encryption 8.4), and the bootstrap `Admin` role, which runs the retained stack's first
     apply from local state (ADR-0005).
  The code added what the threat model asks of the same guards: SCP 4 also denies IAM access keys to everyone and IAM
  users, their passwords, policies and MFA devices to all but `Admin` (T-71, T-74, #81), and SCP 1 denies KMS
  replicas outside Osaka (encryption 4.4) and VPC endpoints to services outside Japan.
- **Root users.** Centralized root access is on: member accounts have no root credentials, and a privileged root task
  runs from the management account through `sts:AssumeRoot`, which SCP 3 lets through. Only the management account's
  root user has a password and security keys.
- **The shared account** lives from the bootstrap until the last environment is torn down. It is CloudTrail's
  delegated administrator and creates the organization trail next to its log archive, so the management account holds
  no trail. GuardDuty and Config belong to each environment and have no delegated administrator. The organization trail
  writes to its log archive under Object Lock with 90-day retention (T-75), so after the final teardown it keeps
  billing a few cents for up to 90 days, the small exception NFR-19 records. The retained stack keeps its own trail
  (encryption 8.4), because the organization trail ends with the shared account.
- **Cross-account access**: each environment's node role pulls from ECR in shared (repository policy, and the registry
  key through ECR only); the release workflow pushes through an OIDC role in shared; each environment's apply role
  reads the web bundle artifacts and writes its own DNS records in the shared zone through a role limited to its names
  (ADR-0021); the organization trail writes to the log archive, and each environment's own trail delivers the S3 data
  events on its files buckets there too, under Object Lock (authn-authz 8.3), where only that environment's lifecycle
  jobs role may read its own trail's prefix, for the NFR-15 match.
- **Budgets per account** follow capacity 7.3: dev $500, staging $800, prod $5,180 and shared $20, together the $6,500
  cap, and $7 for prod after teardown.
- **Before anything is applied**, the maintainer names the profiles, and any workloads already in the personal
  account move out or are removed, because SCPs won't apply to it once it is the management account.

When to revisit: when a second maintainer joins (split the management account's duties from operating); if the
service ever holds real customer data, which justifies separate security tooling and log archive accounts; or if
Identity Center can serve sign-in from Osaka.
