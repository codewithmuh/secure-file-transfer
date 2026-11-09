# Runbook: ArgoCdApplicationUnhealthy

The Argo CD alert of architecture 6 ("Argo CD sync alerts"; ADR-0004, ADR-0005), defined in
[`deploy/alerts/platform.rules.yaml`](../../deploy/alerts/platform.rules.yaml). Severity: ticket. Its `condition`
label says which, and `name` names the Application (`root`, `sft` or `sft-operator`):

- `health`: the Application's health is neither Healthy, Progressing nor Suspended for 15 minutes;
- `sync`: it has been out of sync with Git for 30 minutes.

Suspended is normal: `invite-backlog` is a CronJob that is always suspended, and Osaka's pilot light suspends every
job.

## Symptoms

What runs in the cluster differs from what Git says. A promotion, a fix, a rollback or a fencing commit isn't reaching
the cluster (T-78).

## Impact

Usually none yet: the previous version keeps running. But the next change, including an urgent rollback (NFR-18), won't
apply until the sync works, and the promotion gate won't pass a promotion from this environment.

## Confirm

Argo CD's UI, read-only for `ReadOnly` and `Operator`, through the Systems Manager tunnel (authn-authz 8.1): the
Application's sync result, its conditions and the resources that aren't healthy. Or:

```bash
kubectl -n argocd get applications
kubectl -n argocd describe application <name> | sed -n '/Conditions/,$p'
kubectl -n sft get pods | grep -v Running              # the unhealthy workloads
```

Common causes:

- the migration PreSync hook failed or refused the image (ADR-0005, data model 7): `kubectl -n sft logs job/migrate`;
- an image that admission refused: Kyverno's events name the policy (an unsigned or unmirrored image, ADR-0007);
- a pod that never gets ready: [service-unavailable.md](service-unavailable.md);
- Argo CD can't reach GitHub: the egress proxy's `argocd` listener ([egress-proxy.md](egress-proxy.md));
- a manifest the AppProject `sft` doesn't allow (a kind or namespace outside its list).

## Mitigate

1. **Fix it in Git.** Nobody syncs, changes or overrides an Application by hand: Argo CD's roles are read-only for
   people (authn-authz 8.1, ADR-0004). Revert the commit that broke it, or fix forward in a pull request.
2. **A failed migration** stops the sync before any pod changes; roll back the version change and fix the migration
   (migrations are expand-only, architecture 3.3).
3. **Out of sync because of drift** (something changed in the cluster): self-heal puts it back; if it can't, find what
   changed it. Nothing but Argo CD should write in `sft` and `sft-operator`.

## Escalate

If an urgent change can't reach prod, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Note the cause; a check that would have caught it in CI (deploy/check.sh, the rendered-manifest tests) is the action.
