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
  trusts pinned to this repository, no long-lived keys, Argo CD syncing only reviewed `main`, and Terraform state that
  is encrypted, locked and holds no secrets.
- **Constraints.** One account per environment ([ADR-0006](0006-aws-account-per-environment.md)), a cluster per
  environment and region ([ADR-0004](0004-compute-eks-karpenter-argo-cd.md)), one maintainer (R-08), and nothing applied
  until the maintainer names the AWS profiles. The template's CI already lints workflows, scans for secrets and
  misconfigurations with gitleaks and Trivy, pins actions to SHAs and runs release-please.

## Decision

- **Terraform** for every AWS resource, in small root modules per account, environment, region and layer (bootstrap,
  network, data, cluster, cluster bootstrap, edge, and the retained stack in prod), built from shared modules so Tokyo
  and Osaka come from the same code (T-79). Osaka has its own root modules and states, so nothing in Osaka needs
  Tokyo's APIs to plan or apply.
- **State** in one S3 bucket per environment account and region, Osaka's states in an Osaka bucket: versioned,
  encrypted with that region's tfstate key, locked with S3 native locking (`use_lockfile`, no DynamoDB table), and
  readable only by that account's Terraform roles (T-73). The plan role may write only the `.tflock` lock objects and
  use the tfstate key only to decrypt and generate data keys; it can't write state.
- **GitHub Actions with OIDC.** Each account has a plan role for pull requests and an apply role for `main`, and they
  trust different subjects (T-71): the plan role only `repo:codewithmuh/secure-file-transfer:pull_request`, the apply
  role only its GitHub environment, for example `repo:codewithmuh/secure-file-transfer:environment:prod`. Each GitHub
  environment accepts deployments from `main` only, so no pull request job can obtain an apply role's subject. Applies
  run after merge, dev → staging → prod, and prod waits for the environment's approval.
- **Argo CD in each cluster**, pulling the deploy config from `main` only: a Helm chart for the application and one
  values file per environment and region that pins the image digests. Auto-sync with prune and self-heal everywhere;
  nobody changes or syncs an Application by hand (ADR-0004).
- **Migrations** run in an Argo CD PreSync job ([ADR-0002](0002-api-framework.md)) and are expand-only towards the
  release before them: they add what the new code needs and remove only what that release no longer uses (data model
  7). Each release ships the list of earlier application revisions its schema still serves. The job runs
  `alembic upgrade head` only when the image's head revision is newer than the database's, and records that list with
  the new head. When the database is ahead, as after a rollback, the job checks that the image's revision is in the
  list recorded for the database's head and skips; if it isn't, the job fails and the sync stops before any pod
  changes. Rollback never runs a down-migration.
- **Promotion through Git.** Every merge to `main` that changes code builds once and opens a pull request that sets
  dev to the new image digests and web bundle version. The build workflow ignores changes under `deploy/`
  (`paths-ignore`) and commits by the bot, so merging a promotion pull request never starts a build. Promoting to
  staging, then prod, is a pull request that copies the previous environment's versions. A required GitHub Actions job
  on it, `promotion-gate`, checks the previous environment's health and passes or fails on the pull request's own head
  commit: its Argo CD applications are synced and healthy on those digests, and the synthetic probe has passed against
  them. Merging the prod pull request is the prod approval. **Rollback** reverts the promotion commit: Argo CD syncs
  the previous digests, the migration job skips, and the web pipeline restores the previous bundle.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Terraform, GitHub Actions with OIDC, Argo CD** (chosen) | Git is the record of what runs where, and a revert is a rollback. Argo CD pulls from inside each cluster, so CI holds no deploy credentials, drift is corrected, and a returning Tokyo cluster is fenced by Git (T-78). The Osaka pilot light's Argo CD stays in sync with Git, so a failover only changes what Git holds (ADR-0004). Terraform covers every AWS service we use, plans are reviewable in the pull request, and Trivy already scans it. | Two tools and two deploy paths to understand: Terraform applies from CI, Argo CD syncs from inside. State buckets and locks in every account and region, and the bootstrap of each account, are ours to run. Each promotion is a pull request, and a pull request needs CI, which bounds how fast a rollback can merge. Five Argo CD instances to upgrade. |
| **Terraform for everything, Kubernetes included** | One tool, one state and one pipeline. | Kubernetes objects in Terraform state; nothing reconciles drift between applies; CI needs admin credentials into every cluster; rollback is re-applying an older configuration; the Osaka cluster can't start syncing by itself after a failover. |
| **Push deploys from GitHub Actions** (`helm upgrade` in CI) | Simple; the deploy result shows in the workflow run. | CI holds credentials to every cluster (T-72); nothing corrects drift; fencing Tokyo after a failover needs CI to reach a cluster that may be unreachable (T-78); a rollback needs CI to run. |
| **Flux instead of Argo CD** | Lighter: no API server, repository server or Redis; Kubernetes-native resources. | Mostly a preference, since both meet the requirements. The project's stack and NFR-18's measurement name Argo CD, and Argo CD's sync waves, hooks, health reporting and notifications map directly onto the migration job and the promotion gate. |
| **CloudFormation or AWS CDK** | AWS keeps the state and rolls back a failed stack; no state bucket to protect. | Deploying the same stacks to five accounts and two regions needs StackSets or a CDK pipeline; the threat model's checks (Trivy on Terraform, write-only arguments for the master password, encryption 6.3) assume Terraform; slower feedback on some resources. |

## Consequences

- **Build once.** CI on `main` builds the image, scans it, signs it and pushes it to ECR by Git SHA
  ([ADR-0007](0007-container-registry-ecr.md)), and builds the web bundle and stores it by version
  ([ADR-0008](0008-web-app-s3-cloudfront.md)). release-please still writes versions and the changelog; a release
  points at digests already built from `main` and never rebuilds.
- **Bot pull requests** use the GitHub App token from
  [#6](https://github.com/codewithmuh/secure-file-transfer/issues/6), so CI runs on them. Each digest is tagged
  deployed once its pin lands on `main`, which keeps it from expiring (ADR-0007).
- **What the gate reads.** Argo CD's notifications controller records each application's sync, health and image
  digests as a GitHub deployment status for its environment and region (named apart from the GitHub environments the
  apply roles trust), through a GitHub App limited to deployments, over the egress proxy
  ([ADR-0021](0021-network-design-and-egress.md)). The synthetic probe publishes its result per digest as a CloudWatch
  metric, which `promotion-gate` reads through the previous environment's plan role. The job waits up to 30 minutes and
  can be re-run.
- **Fast reverts.** For a pull request that touches only `deploy/`, CI skips the code jobs but still reports the
  required checks as passed, and checks that every digest exists in ECR and is signed (not yet: no role a pull request
  may assume reads the registry, ADR-0007). `promotion-gate` passes a revert
  at once when every digest it restores is one that environment ran before, from its deployment history. A revert then
  merges within minutes, inside NFR-18's 10 minutes.
- **Bootstrap exceptions.** Each account's bootstrap stack (a state bucket and tfstate key per region, the OIDC
  provider, the plan and apply roles, and the key-administration role of
  [ADR-0017](0017-kms-keys-per-data-class.md)) and the retained stack start with local state, applied by the
  maintainer with the time-boxed `Admin` permission set (ADR-0006), then move their state into their bucket
  (encryption 8.4). The organization stack is applied by the maintainer, not from CI (ADR-0006).
- **Cluster bootstrap.** Argo CD's Helm release is in a `cluster-bootstrap` root module per cluster, planned and
  applied only on `main` by the job that opens the Systems Manager tunnel (ADR-0021), so pull request plans never reach
  a cluster API. Osaka's always-on `system` node (ADR-0004) is the tunnel's end there, so Osaka's Argo CD is installed
  and upgraded like Tokyo's.
- **Failover runs from Osaka.** Osaka's root modules keep their state and locks in Osaka, so the failover's one
  Terraform step, scaling Osaka's `system` group, needs nothing from Tokyo. Fencing Tokyo, and taking Osaka out of
  pilot-light mode, is a Git change (T-78). How Tokyo's own state is protected against losing the region is part of
  the disaster recovery review ([#42](https://github.com/codewithmuh/secure-file-transfer/issues/42)).
- **Pinned tools.** Terraform ≥ 1.11, for S3 native locking and write-only arguments, pinned in `required_version`;
  the AWS provider pinned and updated by Dependabot.
- **Static checks until the profiles exist:** `terraform fmt` and `validate`, tflint, Trivy's misconfiguration scan,
  and custom Rego checks run by Trivy for OIDC trust pins (a plan role trusts only `pull_request`, an apply role only
  its environment), wildcard IAM actions and the retained stack's guards (encryption 8.4). No plan runs against a real
  account before then.
- **GitHub plan limits.** Environment approvals, environment branch rules and the `protect-main` ruleset are enforced
  only on a public repository or a paid plan; the prod gate and the apply roles' trust depend on them (T-71, T-72).
- **Argo CD's Git access.** Argo CD reads the repository over HTTPS through the egress proxy. A private repository
  needs a read-only credential that reaches a new cluster before External Secrets runs; a public one needs none.

When to revisit: if Terraform applies are what keeps the rebuild over NFR-19's 2 hours; if the pull request per
promotion makes several releases a week a chore; or when a second maintainer joins, which adds required approvals on
promotion pull requests (R-08).
