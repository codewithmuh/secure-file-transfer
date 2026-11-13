# Documentation

Every document about Secure File Transfer, grouped by who reads it and what it answers. Start with the
[README](../README.md) for what the product is and where it stands.

## Evaluating the product

For engineering leaders, architects and anyone deciding whether the design is credible.

| Document | What it answers |
|---|---|
| [Product requirements (PRD)](prd.md) | What v1 does, for whom and what it leaves out, and the measurable targets it is held to |
| [Architecture](architecture.md) | How it is built: containers, deployment in Tokyo and Osaka, every key flow, failure handling and the disaster-recovery outline |
| [Capacity and cost](design/capacity-and-cost.md) | The design load, how each part is sized for it, and what each environment costs a month |
| [Delivery plan](delivery-plan.md) | The order it was built in: milestones as thin vertical slices, and the definition of done |
| [Service level objectives](operations/slos.md) | The objectives the service is measured against, and the alerts that guard them |

## Building and running it

For engineers who want to run it locally, change it or call its API.

| Document | What it answers |
|---|---|
| [Local development](local-development.md) | How to run the whole service on a laptop, sign in as each user, test every flow, and where the local stand-ins differ from AWS |
| [API contract](api/README.md) | How callers authenticate, and the conventions for errors, pagination, idempotency, rate limits, uploads and downloads |
| [OpenAPI document](api/openapi.yaml) | Every operation, its schemas and its permission, in OpenAPI 3.1 |
| [Data model](design/data-model.md) | Every table, the state machines, the multi-tenancy model, indexes, retention and migrations |
| [DLP detectors](design/dlp-detectors.md) | How a file is inspected: text extraction, the built-in detectors, tenant keywords and patterns, the default policy and the accuracy tests |
| [Contributing](../CONTRIBUTING.md) | The workflow from issue to merged pull request, the standards and the contribution terms |

The code's own READMEs: the [API service](../services/api/README.md), the [web app](../web/README.md), the
[deploy config](../deploy/README.md) and the [infrastructure](../infra/README.md).

## Operating it

For whoever runs staging and prod: deploying, watching, recovering and tearing down.

| Document | What it answers |
|---|---|
| [Service level objectives](operations/slos.md) | Each objective with its indicator and error budget, the burn-rate alerts, drill windows, alert routing and coverage |
| [Metrics catalogue](operations/metrics.md) | Every metric the service exposes, where it comes from and which SLO or alert reads it |
| [Observability](operations/observability.md) | How each cluster collects metrics, logs and traces, how alerts leave it, and how to change the stack |
| [Performance](operations/performance.md) | How the design-load test, the DLP inspection benchmark and the resumable upload test run, and their results |
| [Disaster recovery](operations/disaster-recovery.md) | The recovery targets, what protects which data, the drill scripts, the recovery job and the decisions behind them |
| [Drill log template](operations/drill-log-template.md) | What every drill and every real recovery records |
| [Runbooks](runbooks/README.md) | One page per alert and alarm, and the procedures run on purpose |

The procedures an operator runs on purpose, all listed in the runbook index:

- Build the platform: [create the organization and bootstrap the accounts](runbooks/organization-and-bootstrap.md),
  then [build staging and prod](runbooks/apply-staging-and-prod.md).
- Recover: [regional failover](runbooks/regional-failover.md), [failback](runbooks/regional-failback.md),
  [Availability Zone failure](runbooks/az-failure.md) and [point-in-time restore](runbooks/point-in-time-restore.md),
  with [drills that don't page](runbooks/drill-in-progress.md).
- Run prod: the [operating period](runbooks/operating-period.md), the [synthetic probe](runbooks/synthetic-probe.md),
  [field keys](runbooks/field-keys.md), the [metadata purge](runbooks/metadata-purge.md) and
  [break-glass access](runbooks/break-glass.md).
- End it: [teardown](runbooks/teardown.md).

## Reviewing its security

For security reviewers and anyone assessing the risk of running it.

| Document | What it answers |
|---|---|
| [Threat model](threat-model.md) | The assets and trust boundaries, every threat by STRIDE with its mitigation, the accepted residual risks, and the test that proves each group of mitigations |
| [Authentication and authorization](security/authn-authz.md) | How members, recipients, uploaders, API keys and operators prove who they are; sessions, roles, tenant isolation and break-glass |
| [Encryption and key management](security/encryption-and-keys.md) | What is encrypted in transit and at rest, which KMS keys exist and who may use them, application secrets, rotation and deletion |
| [Abuse prevention and rate limits](security/abuse-and-rate-limits.md) | Every rate limit and where it is enforced, the WAF, the download mechanism, upload and email abuse, and monitoring |
| [Security policy](../SECURITY.md) | How to report a vulnerability, and how the repository protects itself |

The decisions behind the security design are ADR-0016 to ADR-0022, below.

## The decision record

One architecture decision record per significant choice, each with the options considered and the trade-offs
([ADR-0001](adr/0001-record-architecture-decisions.md) explains the format; new ones start from the
[template](adr/0000-template.md)).

| ADR | What it decides |
|---|---|
| [0001](adr/0001-record-architecture-decisions.md) | Record significant decisions as ADRs |
| [0002](adr/0002-api-framework.md) | The API framework: FastAPI with SQLAlchemy and Alembic |
| [0003](adr/0003-multi-tenancy-shared-schema.md) | Multi-tenancy: one shared schema with `tenant_id` on every row |
| [0004](adr/0004-compute-eks-karpenter-argo-cd.md) | Compute: EKS with Karpenter and Argo CD |
| [0005](adr/0005-terraform-github-actions-argo-cd.md) | Building and delivering: Terraform, GitHub Actions with OIDC, and Argo CD |
| [0006](adr/0006-aws-account-per-environment.md) | One AWS account per environment under AWS Organizations |
| [0007](adr/0007-container-registry-ecr.md) | Container images in ECR in a shared account, signed and pinned by digest |
| [0008](adr/0008-web-app-s3-cloudfront.md) | Hosting the web app on S3 and CloudFront |
| [0009](adr/0009-observability-opentelemetry-self-hosted.md) | Observability: OpenTelemetry with self-hosted Prometheus, Grafana, Loki and Tempo |
| [0010](adr/0010-no-go-in-v1.md) | Python only in v1 |
| [0011](adr/0011-database-aurora-global.md) | The database: Aurora PostgreSQL with a global database secondary in Osaka |
| [0012](adr/0012-object-storage-s3.md) | Object storage: S3 with versioning and replication to Osaka |
| [0013](adr/0013-queues-sqs-outbox.md) | Queues: SQS with dead-letter queues, fed by a transactional outbox |
| [0014](adr/0014-rate-limit-counters.md) | Rate-limit counters: ElastiCache Serverless for Valkey and WAF rate rules |
| [0015](adr/0015-email-ses.md) | Email: Amazon SES in Tokyo and Osaka |
| [0016](adr/0016-member-sign-in-cognito.md) | Member sign-in: Cognito with mandatory MFA and federated tenant SSO |
| [0017](adr/0017-kms-keys-per-data-class.md) | Keys: shared KMS keys per data class, and per-tenant data keys |
| [0018](adr/0018-stream-downloads-through-api.md) | Downloads: streamed through the API under session-bound grants |
| [0019](adr/0019-malware-scanning-clamav-guardduty.md) | Malware scanning: ClamAV up to 2 GB, GuardDuty Malware Protection above |
| [0020](adr/0020-row-level-security.md) | PostgreSQL row-level security as a second tenant isolation layer |
| [0021](adr/0021-network-design-and-egress.md) | The network: private clusters, egress through VPC endpoints or an allowlisting proxy |
| [0022](adr/0022-dlp-inspection-engine.md) | DLP inspection: our own detectors, in sandboxed pods beside the scan workers |
