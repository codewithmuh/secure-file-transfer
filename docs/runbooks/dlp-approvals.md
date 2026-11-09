# Runbook: DlpApprovalBacklog

The DLP approval alert of architecture 6 ("Approvals not decided"; FR-43, architecture 4.6; abuse 8.2,
`DlpApprovalBacklog`), defined in
[`deploy/alerts/dlp-approvals.rules.yaml`](../../deploy/alerts/dlp-approvals.rules.yaml). Severity: ticket.

## Symptoms

In the last hour a tenant's sender asked for an approval that nobody could give: `confirmTransfer` answered
`409 no_eligible_approver`, and every active admin of the tenant was emailed `dlp_no_eligible_approver`
(`emails_sent_total{type="dlp_no_eligible_approver"}`), or would have been but for the cap of 3 a day per tenant
(`email_caps_hit_total{cap="tenant_no_eligible_approver"}`).

`DlpApprovalBacklog`'s other half, a pending request older than half the tenant's approval timeout, waits for its
metric (`dlp_oldest_pending_approval_seconds`, docs/operations/slos.md).

## Impact

The tenant's DLP rules require approval, but approver designations changed so that no one but the sender, or too few
people for a two-approver rule, remains (architecture 4.6). Its transfers that match those rules can't be sent: each
confirmation is rolled back and stays with its sender. Nothing is shared without a decision (FR-43).

## Confirm

Metrics carry no tenant. The notifier's logs for the `dlp_no_eligible_approver` messages carry the `tenant_id`:

```bash
kubectl -n sft logs deploy/notifier --since=2h | grep dlp_no_eligible_approver
```

The tenant's audit log holds each refusal; its admins can read it, operators can't (FR-28).

## Mitigate

1. **This is the tenant's to fix.** Its admins have been emailed. A tenant admin, with step-up, designates more
   approvers, or changes the rule so it needs fewer (architecture 4.6, FR-43).
2. If the admins don't act within a working day, the operator contacts the tenant through its usual channel, naming the
   time of the refusals, never transfer details.
3. A tenant whose admins are all gone (deactivated, demoted) can't fix it alone: the operator's tenant tools
   (`getTenant`) show its state; restoring an admin is a support case for the owner.

## Escalate

Escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS) only if the tenant has no active admin, or asks for
help.

## Afterwards

If it recurs, consider whether the web app should warn an admin before a designation change leaves a rule without
enough approvers.
