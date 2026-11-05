# secure-file-transfer

<p align="center">
  <a href="https://github.com/codewithmuh/secure-file-transfer/actions/workflows/ci.yml"><img src="https://github.com/codewithmuh/secure-file-transfer/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-blue.svg?style=flat-square" alt="License: PolyForm Noncommercial 1.0.0"></a>
</p>

<p align="center">
  Copyright © 2026 Muhammad Rashid (<a href="https://codewithmuh.com">CodeWithMuh</a>) ·
  <a href="mailto:contact@codewithmuh.com">contact@codewithmuh.com</a><br>
  Free to read, run and learn from. Commercial use is not allowed without a licence: see <a href="#license">License</a>.
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

**Building milestone M0** (foundation) of the [delivery plan](docs/delivery-plan.md). Planning phases 1–5 are done.
The API service skeleton in `services/api` replaces the
[production repo template](https://github.com/codewithmuh/production-repo-template)'s sample service: its layers,
settings, probes, metrics, logs and graceful shutdown are in place, and it serves no API routes yet.

## What v1 will do

| Capability | Summary |
|---|---|
| Send | Upload files and share them with external recipients by a link that expires |
| Request | Send an upload link so someone outside the company can deliver files to you |
| Verify | Recipients prove they own their email address before they download |
| Protect | Files encrypted at rest with KMS keys and in transit with TLS; malware scan before any download |
| Prevent data loss | Files inspected for personal data and secrets, such as My Numbers and card numbers; the company's rules warn the sender, hold the transfer for an approver, or block it before anything leaves |
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
| 5. Delivery plan | GitHub milestones and issues, built in thin vertical slices | [#43] |
| 6. Operations | SLOs, dashboards, alerts, runbooks, backup/restore and DR drills with measured RTO/RPO | — |

Stack, as the phase 4 ADRs decided ([architecture](docs/architecture.md) section 9): Python (FastAPI) only, Aurora
PostgreSQL, Amazon S3 + KMS, Kubernetes (EKS with Karpenter) with Argo CD, Terraform, and GitHub Actions with OIDC,
plus SQS, SES, Cognito, ElastiCache for Valkey, and ClamAV with GuardDuty Malware Protection for scanning. The design
keeps the moving parts few: one API service plus workers, and one system of record.

## How changes flow

Issue first, one branch per issue (or per batch of related issues), then a pull request with a Conventional Commit
title that closes them. It needs a code review and green CI before a squash merge into `main`.
[CONTRIBUTING.md](CONTRIBUTING.md) has the details, including the `main` ruleset and its one temporary exception
([#6]).

release-please keeps a Release PR open. Merging it tags the version, and `release.yml` publishes a signed image with
an SBOM to GHCR, until M4 moves images to ECR in the shared account ([ADR-0007](docs/adr/0007-container-registry-ecr.md)).

## Local development

Requirements: [uv](https://docs.astral.sh/uv/), [pre-commit](https://pre-commit.com/), Docker and Node (the version in
`web/.nvmrc`), or just open the **Dev Container**.

```bash
make setup    # install dependencies and the git hooks (gitleaks runs on every commit)
make check    # lint, type-check and test everything (same as CI)
make up       # run the API on :8000 with the local stack that stands in for AWS
make smoke    # one round trip to every service of the local stack
make down     # stop; `make reset` also deletes the local data
```

Run `make` with no arguments to list every command. [Local development](docs/local-development.md) lists the
services of the local stack, their ports and credentials, and how they differ from AWS.

## Repository layout

```
.github/                 workflows, Dependabot, CODEOWNERS, issue + PR templates
.devcontainer/           reproducible dev environment
infra/                   Terraform for AWS, checked statically and not applied yet (infra/README.md)
docs/                    PRD, architecture, design notes, API contract, threat model, security design, ADRs, runbooks
services/api/            API service (FastAPI); the workers will share its codebase
web/                     web app (React + TypeScript, served from S3 and CloudFront, ADR-0008); `make web-check`
compose.yaml             local run with production-like hardening
local/                   configuration and smoke checks of the local stack
Makefile                 every command you need
```

## Service contract

Every service keeps this runtime contract:

| Endpoint / behaviour | Meaning |
|---|---|
| Ports | The API on `PUBLIC_PORT` (8000); probes and metrics only on `INTERNAL_PORT` (8001), which the public load balancer never routes |
| `GET /healthz` | Liveness: the process is up (never checks dependencies) |
| `GET /readyz` | Readiness: 503 until started and while shutting down; the load balancer's target health check. There is no public health endpoint |
| `GET /metrics` | Prometheus metrics: request count and latency by route template and status, plus process metrics |
| Logs | JSON on stdout, one line per event. Lines logged during a request carry its `request_id` (always generated by the service, also in the `X-Request-Id` response header) and `trace_id` (from a valid W3C `traceparent` header, or new) |
| `SIGTERM` | Fail readiness → stop accepting, finish in-flight requests (≤ 20 s; the API's download streams ≤ 120 s) → exit 0. In Kubernetes a `preStop` sleep keeps the pod accepting until the load balancer has stopped sending to it |
| Config | Environment variables only, typed and checked at startup; secrets have no defaults |
| Image | Non-root user, read-only filesystem, no capabilities, built-in `HEALTHCHECK` |

## Security

No secrets in git: gitleaks runs in pre-commit and in CI, and runtime secrets will live in AWS Secrets Manager. To
report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE) © 2026 Muhammad Rashid
([CodeWithMuh](https://codewithmuh.com)). It is not open source.

- **Free** to read, run and change for learning, personal projects, research, teaching and non-profit use.
- **Commercial use needs a licence**: running it for a company or its customers, hosting it as a service, or using the
  code in a product or in paid client work.

[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) explains what is allowed and how to get a commercial licence. Contact:
[contact@codewithmuh.com](mailto:contact@codewithmuh.com) ·
[LinkedIn](https://www.linkedin.com/in/muhammad-rashid-daha) · [YouTube](https://youtube.com/@codewithmuh).

[#2]: https://github.com/codewithmuh/secure-file-transfer/issues/2
[#6]: https://github.com/codewithmuh/secure-file-transfer/issues/6
[#16]: https://github.com/codewithmuh/secure-file-transfer/issues/16
[#25]: https://github.com/codewithmuh/secure-file-transfer/issues/25
[#34]: https://github.com/codewithmuh/secure-file-transfer/issues/34
[#41]: https://github.com/codewithmuh/secure-file-transfer/issues/41
[#43]: https://github.com/codewithmuh/secure-file-transfer/issues/43
