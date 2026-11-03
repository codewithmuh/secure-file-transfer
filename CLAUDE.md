# secure-file-transfer

A production-grade secure file transfer service on AWS. A company sends confidential files to outside recipients by an
expiring link, or sends an upload link so an outsider can deliver files to it. Recipients verify their email before
download; files are encrypted with KMS, scanned for malware before they become downloadable, and every action is
audit-logged; admins can revoke a link at any time.

It is a reference service built to the standard of a real B2B SaaS team, not a production business. Say so in the
README.

## Background

Read `.private/kickoff.md` at the start of a session (local only, never pushed): the background, Rashid's original
request, the design notes and the decisions made so far. The repo is public at
https://github.com/codewithmuh/secure-file-transfer.

## How we work

Follow the workflow in [CONTRIBUTING.md](CONTRIBUTING.md): plan → issue → branch → PR → code review → merge. No work
without an issue. Rashid commits, pushes and merges; Claude writes code, opens issues and PRs with `gh`, and reviews.
Claude never runs `git commit`, `git push` or a merge: when work is ready, give Rashid the commit message and the exact
files to stage.

Plan like a large company, in this order, each phase producing documents in `docs/` through its own issue and PR:

1. **Requirements:** a PRD with users, use cases, non-goals, and measurable non-functional requirements (availability,
   latency, file size limit, retention).
2. **Architecture and system design:** context and container diagrams, upload and download flows, data model, API
   contract (OpenAPI), multi-tenancy model, capacity estimates.
3. **Security design:** threat model (STRIDE), encryption and key management, authn/authz, abuse and rate limiting.
4. **Decisions:** one ADR in `docs/adr/` per significant choice, with the options considered and the trade-offs.
5. **Delivery plan:** GitHub milestones and issues, built in thin vertical slices.
6. **Operations:** SLOs, dashboards, alerts, runbooks, backup/restore and DR drills with measured RTO/RPO.

## Rules

- Start from the template `codewithmuh/production-repo-template` (Rashid's P0 base for every project).
- Candidate stack, to confirm with ADRs in phase 4: Python (FastAPI), PostgreSQL, S3 + KMS, Kubernetes (EKS) with
  Argo CD, Terraform, GitHub Actions with OIDC. Add Go only where it earns its place.
- Keep the moving parts few: one API service plus workers, one system of record. Don't add services for keywords.
- No secrets in git, ever: gitleaks in pre-commit and CI; secrets live in AWS Secrets Manager.
- AWS: use only the personal AWS profile Rashid provides. Until then, write and statically check the IaC; no
  `terraform apply`, no plans against real accounts, and never the default CLI identity.
- No AI attribution in commits or PRs.
