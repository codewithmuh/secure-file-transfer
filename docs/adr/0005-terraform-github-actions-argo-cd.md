# 0005. Use Terraform, GitHub Actions with OIDC and Argo CD to build and deliver

- Status: accepted
- Date: 2026-11-03
- Issue: [#31](https://github.com/codewithmuh/secure-file-transfer/issues/31)

## Context

- **Promotion and rollback.** The same image digests and the same versioned web app bundle move dev → staging → prod,
  deploys have no downtime, rollback takes ≤ 10 minutes, and releases several times a week are routine (NFR-18). The
  flow is sketched in [architecture](../architecture.md) 3.3: Terraform owns AWS, Argo CD owns what runs in Kubernetes.
- **Rebuild and teardown.** prod is built from Terraform and Argo CD in ≤ 2 hours and destroyed in ≤ 1 hour, leaving
  only the audit archive's retained stack (NFR-19, [encryption](../security/encryption-and-keys.md) 8.4). dev and
  staging come and go for their working windows ([capacity](../design/capacity-and-cost.md) A22). Budgets are in
  Terraform (NFR-20).
- **The pipeline is a target.** The [threat model](../threat-model.md) T-69 to T-73 asks for pinned actions, OIDC
  trusts pinned to the repository and a GitHub environment, no long-lived keys, Argo CD syncing only reviewed `main`,
  and Terraform state that is encrypted, locked and holds no secrets.
- **Constraints.** One account per environment ([ADR-0006](0006-aws-account-per-environment.md)), a cluster per
  environment and region ([ADR-0004](0004-compute-eks-karpenter-argo-cd.md)), one maintainer (R-08), and nothing applied
  until the maintainer names the AWS profiles. The template's CI already lints workflows, scans for secrets and
  misconfigurations with gitleaks and Trivy, pins actions to SHAs and runs release-please.

## Decision

- **Terraform** for every AWS resource, in small root modules per account, environment, region and layer (bootstrap,
  network, data, cluster, edge, and the retained stack in prod), built from shared modules so Tokyo and Osaka come
  from the same code (T-79). Osaka has its own root modules and states, so nothing in Osaka needs Tokyo's APIs to plan.
- **State** in one S3 bucket per environment account, in Tokyo: versioned, encrypted with the tfstate key, locked with
  S3 native locking (`use_lockfile`, no DynamoDB table), readable only by that account's Terraform roles (T-73), and
  in staging and prod replicated both ways with Osaka, so state follows a failover and the failback.
- **GitHub Actions with OIDC.** Each account has a read-only plan role for pull requests and an apply role for `main`,
  each trusting only this repository and one GitHub environment, for example
  `repo:codewithmuh/secure-file-transfer:environment:prod` (T-71). Applies run after merge, dev → staging → prod, and
  prod waits for the environment's approval.
- **Argo CD in each cluster**, pulling the deploy config from `main` only: a Helm chart for the application and one
  values file per environment and region that pins the image digests. Auto-sync with prune and self-heal everywhere;
  Alembic migrations run as a pre-sync job and stay backwards compatible ([ADR-0002](0002-api-framework.md)).
- **Promotion through Git.** Every merge to `main` builds once and opens a pull request that sets dev to the new image
  digests and web bundle version. Promoting to staging, then prod, is a pull request that copies the previous
  environment's versions; it can merge only when Argo CD reports them healthy there. Merging the prod pull request is
  the prod approval. **Rollback** reverts the promotion commit: Argo CD syncs the previous digests, and the web
  pipeline restores the previous bundle.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Terraform, GitHub Actions with OIDC, Argo CD** (chosen) | Git is the record of what runs where, and a revert is a rollback. Argo CD pulls from inside each cluster, so CI holds no cluster credentials, drift is corrected, and a returning Tokyo cluster is fenced by Git (T-78). The Osaka pilot light starts syncing as soon as nodes join (architecture 3.2). Terraform covers every AWS service we use, plans are reviewable in the pull request, and Trivy already scans it. | Two tools and two deploy paths to understand: Terraform applies from CI, Argo CD syncs from inside. State buckets, locks and the bootstrap of each account are ours to run. Each promotion is a pull request, and a pull request needs CI, which bounds how fast a rollback can merge. Five Argo CD instances to upgrade. |
| **Terraform for everything, Kubernetes included** | One tool, one state and one pipeline. | Kubernetes objects in Terraform state; nothing reconciles drift between applies; CI needs admin credentials into every cluster; rollback is re-applying an older configuration; the Osaka cluster can't start syncing by itself after a failover. |
| **Push deploys from GitHub Actions** (`helm upgrade` in CI) | Simple; the deploy result shows in the workflow run. | CI holds credentials to every cluster (T-72); nothing corrects drift; fencing Tokyo after a failover needs CI to reach a cluster that may be unreachable (T-78); a rollback needs CI to run. |
| **Flux instead of Argo CD** | Lighter: no API server, repository server or Redis; Kubernetes-native resources. | Mostly a preference, since both meet the requirements. The candidate stack and NFR-18's measurement name Argo CD, and Argo CD's sync waves, hooks and health reporting map directly onto the migration job and the promotion gate. |
| **CloudFormation or AWS CDK** | AWS keeps the state and rolls back a failed stack; no state bucket to protect. | Deploying the same stacks to five accounts and two regions needs StackSets or a CDK pipeline; the threat model's checks (Trivy on Terraform, write-only arguments for the master password, encryption 6.3) assume Terraform; slower feedback on some resources. |

## Consequences

- **Build once.** CI on `main` builds the image, scans it, signs it and pushes it to ECR by Git SHA
  ([ADR-0007](0007-container-registry-ecr.md)), and builds the web bundle and stores it by version
  ([ADR-0008](0008-web-app-s3-cloudfront.md)). release-please still writes versions and the changelog; a release
  points at digests already built from `main` and never rebuilds.
- **Bot pull requests** use the GitHub App token from
  [#6](https://github.com/codewithmuh/secure-file-transfer/issues/6), so CI runs on them. Argo CD reports sync and health to the commit as a GitHub commit status through a GitHub App
  limited to commit statuses; that status is the promotion gate.
- **Fast reverts.** For a pull request that touches only `deploy/`, CI skips the code jobs but still reports the
  required checks as passed, and checks that every digest exists in ECR and is signed. A revert then merges within
  minutes, inside NFR-18's 10 minutes. Migrations are expand-then-contract, so the previous version runs on the new
  schema and rollback never runs a down-migration.
- **Bootstrap exceptions.** Each account's bootstrap stack (state bucket, tfstate key, OIDC provider, plan and apply
  roles) and the retained stack start with local state, applied by the maintainer, then move their state into their
  bucket (encryption 8.4). The organization stack is applied by the maintainer, not from CI (ADR-0006).
- **Failover runs from Osaka.** The runbook points the backend at the Osaka replica of the state bucket, clears a lock
  file that replication carried over, and scales the Osaka `system` node group. Fencing Tokyo is a Git change (T-78).
- **Pinned tools.** Terraform ≥ 1.11, for S3 native locking and write-only arguments, pinned in `required_version`;
  the AWS provider pinned and updated by Dependabot.
- **Static checks until the profiles exist:** `terraform fmt` and `validate`, tflint, Trivy's misconfiguration scan,
  and custom Rego checks run by Trivy for OIDC trust pins, wildcard IAM actions and the retained stack's guards
  (encryption 8.4). No plan runs against a real account before then.
- **GitHub plan limits.** Environment approvals and the `protect-main` ruleset are enforced only on a public
  repository or a paid plan; the prod gate depends on both (T-71, T-72).
- **Argo CD's Git access.** Argo CD reads the repository over HTTPS. A private repository needs a read-only credential
  that reaches a new cluster before External Secrets runs; a public one needs none.

When to revisit: if Terraform applies are what keeps the rebuild over NFR-19's 2 hours; if the pull request per
promotion makes several releases a week a chore; or when a second maintainer joins, which adds required approvals on
promotion pull requests (R-08).
