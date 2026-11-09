# Runbook: service unavailable

## Symptoms

- `/readyz` returns 503 or times out; the load balancer marks targets unhealthy.
- Error rate or latency alert fired for the service.

## Impact

Clients get errors or slow responses. Check the SLO dashboard for how much error budget is being burned.

## Confirm

```bash
curl -fsS https://<host>/readyz            # readiness from outside
kubectl get pods -l app=<service>           # or: docker compose ps
kubectl logs deploy/<service> --tail=100    # JSON logs; filter by request_id
```

## Mitigate

1. **Recent deploy?** Roll back first, investigate second.
2. **Crash loop?** Check the last log lines and `kubectl describe pod` (OOMKilled, failing probe, bad config).
3. **Dependency down?** Readiness will fail by design; fix or fail over the dependency.
4. **Overloaded?** Scale out, then look for the expensive endpoint in the latency metrics.

## The load balancer's alarms

Two CloudWatch alarms page here too, from outside the cluster
([`infra/modules/alarms/load-balancer.tf`](../../infra/modules/alarms/load-balancer.tf)):

- `sft-<env>-<rs>-api-lb-5xx`: the load balancer answered more than 10 5xx of its own a minute for 5 minutes. Requests
  aren't reaching a pod: no healthy target, a target group or listener changed, or the pods refuse TLS.
- `sft-<env>-<rs>-api-no-healthy-targets`: no healthy API target for 3 minutes. Check the TargetGroupBinding and the
  Load Balancer Controller (`kubectl -n sft describe targetgroupbinding api`, `kubectl -n kube-system logs
  deploy/aws-load-balancer-controller`), then the pods' readiness. In Osaka's pilot light the group is empty by design
  and the alarm doesn't notify.

## Escalate

If not mitigated within 30 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Write a blameless postmortem: timeline, impact, root cause, what went well, action items with owners.
