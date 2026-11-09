# Runbook: EgressProxyDown

The egress proxy alert of architecture 6 ("Egress proxy down: both replicas"; ADR-0021), defined in
[`deploy/alerts/platform.rules.yaml`](../../deploy/alerts/platform.rules.yaml). Severity: page.

## Symptoms

No egress proxy replica has reported `envoy_server_live == 1` for 5 minutes: both are down, or Prometheus can't scrape
them (port 9902, `/stats/prometheus`).

You may see the CloudWatch alarm `sft-<env>-<rs>-heartbeat-missing` first, or only: Alertmanager reaches SNS through
the proxy's `platform` listener, so while the proxy is down this page may never leave the cluster
([watchdog.md](watchdog.md); ADR-0009).

## Impact

The proxy (Envoy, two replicas on the `system` nodes, namespace `egress-proxy`) is the only way out to the internet
(architecture 3.1). One listener per workload:

| Listener | Port | Who | What stops |
|---|---|---|---|
| `api` | 3128 | API | New member sign-ins: code exchanges with Cognito and its signing keys |
| `notifier` | 3129 | Notification worker, invite backlog | Cognito invitations |
| `signature-mirror` | 3130 | Signature mirror | ClamAV database updates; scanning goes on with the last signatures |
| `argocd` | 3131 | Argo CD repo server and notifications | Syncs from GitHub, and the deployment statuses the promotion gate reads |
| `platform` | 3132 | Karpenter, Load Balancer Controller, Kyverno, Alertmanager | New nodes' AMI lookups, target registration, signature reads, alert delivery |
| `key-rotation` | 3133 | Key rotation job | Rotating the user pools' client secrets |

Sending, downloads, uploads, scanning, email through SES, and the Osaka writes use VPC endpoints and continue; existing
sessions keep working (architecture 6).

## Confirm

```bash
kubectl -n egress-proxy get pods -o wide            # on the system nodes, ready?
kubectl -n egress-proxy describe pods | tail -40     # OOMKilled, failing readiness on /ready, image pull
kubectl -n egress-proxy logs deploy/egress-proxy --since=30m | tail -50
kubectl get nodes -l eks.amazonaws.com/nodegroup   # are the system nodes there?
```

If the pods are ready, the scrape is what broke: check the observability stack's scrape config, and the proxy's network
policy, which admits metrics only from Prometheus in `monitoring` (`metricsClients` in the chart).

## Mitigate

1. **The system nodes are gone or unhealthy:** the `system` node group is EKS-managed; check it in the EKS console with
   the `ReadOnly` profile, and its Auto Scaling group's activity. A failed AZ is [region-health.md](region-health.md)'s
   question first.
2. **The pods crash** (out of memory, a bad config): the proxy is installed by Terraform, not Argo CD
   (`infra/modules/cluster-bootstrap/egress-proxy.tf`, a Helm release in the `cluster-bootstrap` layer). A recent
   change there is reverted with a commit and applied by CI on `main` through the Systems Manager tunnel. Operators
   can't restart or patch it by hand (authn-authz 8.1).
3. **Too many tunnels** (`maxConnectionsPerListener`, 1024 per listener per replica): one workload is exhausting it;
   find it in the per-listener stats (`envoy_http_downstream_cx_active` by `envoy_http_conn_manager_prefix`, the
   listener's name) and fix that workload.
4. **Sign-in fails but the proxy is live:** a destination changed or DNS Firewall refuses it; the allowlists are in
   `egress-proxy.tf` and `infra/modules/network` (`dns_firewall_allowed_domains`), and must match.

## Escalate

If sign-in stays down for 30 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS): only a
deploy role can change the platform stack.

## Afterwards

Write a blameless postmortem: timeline, sign-ins refused, root cause, action items.
