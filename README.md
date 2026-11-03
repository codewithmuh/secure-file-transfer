# secure-file-transfer

<p align="center">
  <a href="https://github.com/codewithmuh/secure-file-transfer/actions/workflows/ci.yml"><img src="https://github.com/codewithmuh/secure-file-transfer/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License: MIT"></a>
</p>

A secure file transfer service on AWS. A company sends confidential files to outside recipients through a link that
expires, or sends an upload link so someone outside the company can deliver files to it. Recipients verify their email
address before they can download. Every file is encrypted with AWS KMS and scanned for malware before it becomes
downloadable, every action is written to an audit log, and an admin can revoke any link at any time.

> [!NOTE]
> **This is a reference service, not a production business.** It is built to the standard of a real B2B SaaS team
> (requirements, system design, threat model, ADRs, tests, SLOs, runbooks and measured DR drills), but it has no
> customers, no support and no uptime commitment. Do not use it to move real confidential data.

## Status

**Planning, phase 4 of 6** (decisions, [#34]; review fixes, [#41]). The ADRs are recorded and there is no product code
yet. The two sample services from the
[production repo template](https://github.com/codewithmuh/production-repo-template) stay in place, so every CI
pipeline runs against real code until the first vertical slices replace them.

## What v1 will do

| Capability | Summary |
|---|---|
| Send | Upload files and share them with external recipients by a link that expires |
| Request | Send an upload link so someone outside the company can deliver files to you |
| Verify | Recipients prove they own their email address before they download |
| Protect | Files encrypted at rest with KMS keys and in transit with TLS; malware scan before any download |
| Control | Admins revoke any link at any time; every action is written to an audit log |
| Web app | React + TypeScript app for senders and admins, plus the recipient and uploader pages |

The exact scope, non-goals and measurable targets are in the [PRD](docs/prd.md).

## Planning roadmap

Each phase produces documents in `docs/` through its own issue and pull request.

| Phase | Output | Tracking |
|---|---|---|
| 1. Requirements | [PRD](docs/prd.md): users, use cases, non-goals, measurable non-functional requirements | [#2] |
| 2. Architecture and system design | [Architecture](docs/architecture.md): context and container diagrams, upload and download flows; data model, OpenAPI contract, multi-tenancy model, capacity estimates | [#16] |
| 3. Security design | [STRIDE threat model](docs/threat-model.md), [encryption and key management](docs/security/encryption-and-keys.md), [authn/authz](docs/security/authn-authz.md), [abuse and rate limiting](docs/security/abuse-and-rate-limits.md) | [#25] |
| 4. Decisions | [One ADR per significant choice](docs/adr/) | [#34] |
| 5. Delivery plan | GitHub milestones and issues, built in thin vertical slices | — |
| 6. Operations | SLOs, dashboards, alerts, runbooks, backup/restore and DR drills with measured RTO/RPO | — |

Stack, as the phase 4 ADRs decided ([architecture](docs/architecture.md) section 9): Python (FastAPI) only, Aurora
PostgreSQL, Amazon S3 + KMS, Kubernetes (EKS with Karpenter) with Argo CD, Terraform, and GitHub Actions with OIDC,
plus SQS, SES, Cognito, ElastiCache for Valkey, and ClamAV with GuardDuty Malware Protection for scanning. The design
keeps the moving parts few: one API service plus workers, and one system of record.

## How changes flow

Issue first, one branch per issue, then a pull request with a Conventional Commit title that closes the issue. It needs
a code review and green CI before a squash merge into `main`. [CONTRIBUTING.md](CONTRIBUTING.md) has the details,
including the `main` ruleset and its one temporary exception ([#6]).

release-please keeps a Release PR open. Merging it tags the version. Signed images go to ECR in the shared account
from M4 ([ADR-0007](docs/adr/0007-container-registry-ecr.md)).

## Local development

Requirements: [uv](https://docs.astral.sh/uv/), [pre-commit](https://pre-commit.com/) and Docker, or just open the
**Dev Container**.

```bash
make setup    # install dependencies and the git hooks (gitleaks runs on every commit)
make check    # lint, type-check and test everything (same as CI)
make up       # run the API on :8000
make down
```

Run `make` with no arguments to list every command.

## Repository layout

```
.github/                 workflows, Dependabot, CODEOWNERS, issue + PR templates
.devcontainer/           reproducible dev environment
docs/                    PRD, architecture, design notes, API contract, threat model, security design, ADRs, runbooks
services/api-python/     FastAPI sample service (to be replaced by the API service)
compose.yaml             local run with production-like hardening
Makefile                 every command you need
```

## Service contract

Every service keeps this runtime contract:

| Endpoint / behaviour | Meaning |
|---|---|
| `GET /healthz` | Liveness: the process is up (never checks dependencies) |
| `GET /readyz` | Readiness: 503 until started and while shutting down. The load balancer checks it on a port the public listener doesn't route to; there is no public health endpoint |
| `GET /metrics` | Prometheus metrics: request count and latency by route and status |
| Logs | JSON on stdout, one line per request, with `request_id` (taken from `X-Request-Id` or generated) |
| `SIGTERM` | Fail readiness → finish in-flight requests (≤ 20 s; the API's download streams ≤ 120 s) → exit |
| Image | Non-root user, read-only filesystem, built-in `HEALTHCHECK` |

## Security

No secrets in git: gitleaks runs in pre-commit and in CI, and runtime secrets will live in AWS Secrets Manager. To
report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Muhammad Rashid ([CodeWithMuh](https://youtube.com/@codewithmuh))

[#2]: https://github.com/codewithmuh/secure-file-transfer/issues/2
[#6]: https://github.com/codewithmuh/secure-file-transfer/issues/6
[#16]: https://github.com/codewithmuh/secure-file-transfer/issues/16
[#25]: https://github.com/codewithmuh/secure-file-transfer/issues/25
[#34]: https://github.com/codewithmuh/secure-file-transfer/issues/34
[#41]: https://github.com/codewithmuh/secure-file-transfer/issues/41
