# Runbooks

One page per alert. Every alert annotation must link to its runbook; the rules are in
[`deploy/alerts/`](../../deploy/alerts/).

| Alert | Runbook |
|---|---|
| Service unavailable / readiness failing | [service-unavailable.md](service-unavailable.md) |
| `ScanFailed` | [scan-failed.md](scan-failed.md) |
| `DlpInspectorFailing` | [dlp-inspector.md](dlp-inspector.md) |

Each runbook answers: **what is broken, how bad is it, how to confirm, how to mitigate, how to escalate.**

## Procedures

Steps the maintainer runs on purpose, not in answer to an alert.

| Procedure | Runbook |
|---|---|
| Create the AWS organization, its guardrails and budgets, and bootstrap the accounts (M4) | [organization-and-bootstrap.md](organization-and-bootstrap.md) |
