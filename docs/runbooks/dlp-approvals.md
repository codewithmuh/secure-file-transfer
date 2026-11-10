# Runbook: DlpApprovalBacklog

The DLP approval alert of architecture 6 ("Approvals not decided"; FR-43, architecture 4.6; abuse 8.2,
`DlpApprovalBacklog`), defined in
[`deploy/alerts/dlp-approvals.rules.yaml`](../../deploy/alerts/dlp-approvals.rules.yaml). Severity: ticket.

Its `condition` label says which half:

- `no_eligible_approver`: a tenant's rules need approval that nobody can give (below);
- `pending_half_timeout` (#260): a pending request has waited more than half its tenant's approval timeout
  (`dlp_approval_pending_timeout_used_ratio > 0.5` for 10 minutes; the expiry job measures it every 5 minutes, beside
  `dlp_approval_oldest_pending_age_seconds`).

## Symptoms

`no_eligible_approver`: in the last hour a tenant's sender asked for an approval that nobody could give: `confirmTransfer` answered
`409 no_eligible_approver`, and every active admin of the tenant was emailed `dlp_no_eligible_approver`
(`emails_sent_total{type="dlp_no_eligible_approver"}`), or would have been but for the cap of 3 a day per tenant
(`email_caps_hit_total{cap="tenant_no_eligible_approver"}`).

`pending_half_timeout`: a request's approvers haven't acted for half the time the tenant gives them (`PT1H` to `P7D`,
the tenant's DLP policy). When it expires, its transfer goes back to its sender, who may ask again, up to 3 requests
(FR-43, data model 3.6).

## Impact

The tenant's DLP rules require approval, but approver designations changed so that no one but the sender, or too few
people for a two-approver rule, remains (architecture 4.6). Its transfers that match those rules can't be sent: each
confirmation is rolled back and stays with its sender. Nothing is shared without a decision (FR-43).

For `pending_half_timeout`, the approver may simply be away; the tenant's notices already went to them
(`dlp_approval_requested`, and the digest). Requests waiting is normal; many, or one tenant's queue never moving, is
not.

## Confirm

Metrics carry no tenant. For `pending_half_timeout`, the expiry job's run shows the queue, and a read-only query as
the operator in the operator API's tools names the tenants, never a transfer's content:

```promql
max(dlp_approval_oldest_pending_age_seconds) / 3600     # hours the oldest has waited
```

For `no_eligible_approver`, The notifier's logs for the `dlp_no_eligible_approver` messages carry the `tenant_id`:

```bash
kubectl -n sft logs deploy/notifier --since=2h | grep dlp_no_eligible_approver
```

The tenant's audit log holds each refusal; its admins can read it, operators can't (FR-28).

## Mitigate

1. **`pending_half_timeout`: the tenant's approvers decide.** If one tenant's requests keep reaching it, tell its admins
   (through its usual channel) that requests wait for their approvers; they may designate more approvers or lengthen
   the timeout. The operator never decides a request.
2. **`no_eligible_approver`: this is the tenant's to fix.** Its admins have been emailed. A tenant admin, with step-up, designates more
   approvers, or changes the rule so it needs fewer (architecture 4.6, FR-43).
3. If the admins don't act within a working day, the operator contacts the tenant through its usual channel, naming the
   time of the refusals, never transfer details.
4. A tenant whose admins are all gone (deactivated, demoted) can't fix it alone: the operator's tenant tools
   (`getTenant`) show its state; restoring an admin is a support case for the owner.

## Escalate

Escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS) only if the tenant has no active admin, or asks for
help.

## Afterwards

If it recurs, consider whether the web app should warn an admin before a designation change leaves a rule without
enough approvers.
