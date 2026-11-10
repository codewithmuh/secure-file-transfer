# Runbook: build staging and prod, with the Osaka pilot light

The procedure and the inputs for the first apply of staging and then prod (M7, [#247](https://github.com/codewithmuh/secure-file-transfer/issues/247)),
after dev has run. It is a procedure, not an alert. The order of the stacks is
[infra/README.md, "Apply order"](../../infra/README.md#apply-order); this page is what has to be ready before it, what
the Osaka pilot light runs, and how to tell that an environment is up.

> [!IMPORTANT]
> **Nothing here has been applied.** Staging's and prod's roots and values were checked against dev and against
> architecture 3.1 to 3.4 in #247, and they pass `infra/scripts/check.sh` and `deploy/check.sh`; every step below that
> touches AWS is pending the AWS run, and the maintainer runs it with the profiles he names.

## 1. What the maintainer supplies

Nothing in this list is committed. Each goes in at apply time, from the maintainer's own shell or the GitHub
environment, and the stacks refuse to plan without the ones that have no default.

| Input | Where it goes | Used by |
|---|---|---|
| An AWS CLI profile per account: management, shared, dev, staging, prod, each through IAM Identity Center with MFA | The maintainer's shell (`AWS_PROFILE`), never the default identity | Every local apply (bootstrap, organization) |
| The account IDs | `TF_VAR_account_id`, `TF_VAR_shared_account_id` | Every root |
| The domain, `sft.<domain>` under it | `TF_VAR_domain` | `edge`, `identity`, `cluster-bootstrap`, and every `network` root (DNS Firewall's `api.` and `app.` names, #259) |
| SES: production access (out of the sandbox) in Tokyo and Osaka for staging and prod, requested after `identity` makes the domain identity; a mailbox for DMARC reports | AWS Support case per account and Region; `TF_VAR_dmarc_report_address` | `identity` (ADR-0015) |
| The operators' alert addresses (each confirms its SNS subscription by email) | `TF_VAR_alert_emails`, a list | `alarms`, and prod's `retained` (its own alert topics, #263) |
| The API image digest that the sign-in triggers run | `TF_VAR_signin_trigger_image` | `identity` (#238) |
| Argo CD's GitHub App for deployment statuses (needed by the promotion gate) and its Identity Center SAML application | `TF_VAR_github_app`, `TF_VAR_identity_center_saml` | `cluster-bootstrap` |
| The plan roles' ARNs, for the promotion gate to read the probe's result in the previous environment | Repository variables `TF_PLAN_ROLE_ARN_DEV` and `TF_PLAN_ROLE_ARN_STAGING` (outputs of `bootstrap/<env>/ap-northeast-1`) | `.github/workflows/promote.yml` |
| The GitHub environments `staging` and `prod`, deployments from `main` only, before their deploy roles exist (T-71) | Repository settings | `infra/README.md`, step 0 |
| The GitHub environments `prod-retained` (the retained stack's deploy role, #263) and `loadtest-staging` (staging's load test role, #259), deployments from `main` only | Repository settings | `retained`; Tokyo's staging `identity` |
| Whether break-glass may be self-approved in staging or prod while the run has a single operator | A reviewed commit adding `BREAK_GLASS_SELF_APPROVAL: "true"` to the cluster's values, as dev has ([break-glass.md](break-glass.md)); off until then | `operatorApi.env` |
| The operating period's budget (PRD open question 7) | `infra/organization/budgets.tf` | Budgets (NFR-20) |

## 2. Order

1. **Staging, then prod**, each by [infra/README.md, "Apply order"](../../infra/README.md#apply-order): bootstrap in
   both Regions, then for Tokyo and Osaka `network`, `data` (twice in Tokyo, around Osaka's), `cluster`, `edge`,
   `identity`, `cluster-bootstrap`, and last `alarms` (Tokyo's after Osaka's `edge`, for the Route 53 health checks).
   In prod, `retained` goes before `data`.
2. **First deploy**: Argo CD syncs the values in `deploy/environments/<env>/<region>/`; start the key rotation job
   once, then the invitation backlog ([deploy/README.md](../../deploy/README.md), "The first deploy of an
   environment").
3. **Promotion**: staging's digest comes from dev by the promotion pull request (`promote.yml`, `open`); prod's from
   staging. The gate passes once the previous environment is healthy in Argo CD on the digest and its synthetic probe
   has passed its last three runs since the digest landed (ADR-0005).

## 3. The Osaka pilot light

What runs in Osaka while it waits (architecture 3.2), from the same modules as Tokyo, and what it costs
([capacity and cost](../design/capacity-and-cost.md) 5.2, 5.3):

| Part | Staging | Prod |
|---|---|---|
| EKS control plane and the `system` node group | 1 node (`system_node_count = 1`), Argo CD, Kyverno, Karpenter, CoreDNS, the egress proxy; no main or scan nodes | The same |
| Application workloads | `pilotLight: true`: every Deployment at zero, every CronJob suspended, no migration job; the replica counts in the file are what a failover runs | The same |
| Observability | Off: no Prometheus, Alertmanager or Grafana; the heartbeat alarm off (`heartbeat_enabled = false`) and the no-healthy-targets alarm muted (`pilot_light = true`) in Osaka's `alarms` root | The same |
| Database | The global database's secondary on Aurora Serverless v2, 1 to 16 ACU | The secondary on one db.r8g.large, until a drill shows Serverless keeps up |
| Files and archive | Replica buckets of both files bucket pairs and the audit archive, replicated with RTC; no GuardDuty plan on the large-files bucket (`malware_protection_enabled = false`) | The same |
| Network, edge | VPC across 3 AZs, a NAT gateway and every endpoint in each, DNS Firewall, load balancer and WAF, idle | The same |
| Sign-in and email | The standby user pool with no users; SES set up and out of the sandbox | The same |
| Queues, counter store, keys, secrets | Idle queues and dead-letter queues (their alarms stay on), Valkey at its smallest, key and secret replicas | The same |
| Alarms | Dead-letter queues, queue age, NAT, KMS, SES reputation, the sign-in triggers and the database's replication lag | The same |
| Cost, idle | About $818 a month | About $959 a month |

A failover changes, in this order, what [regional-failover.md](regional-failover.md) lists: the fencing commit flips
`pilotLight` in both Regions; Osaka's `cluster` raises `system_node_count` to 2; Osaka's `data` turns on
`malware_protection_enabled`; Osaka's `alarms` applies with `TF_VAR_heartbeat_enabled=true TF_VAR_pilot_light=false`
(infra/modules/alarms). Failback reverses each.

## 4. How to tell it is up

Run in staging first; each is pending the AWS run.

```bash
# Argo CD: every Application Synced and Healthy (read-only, through the tunnel)
kubectl -n argocd get applications
# The alerting pipeline: the heartbeat topic receives a message a minute, and its alarm is OK
aws cloudwatch describe-alarms --alarm-names sft-<env>-apne1-heartbeat-missing --query 'MetricAlarms[0].StateValue'
# The probe: ProbeSuccess = 1 for the last runs
aws cloudwatch get-metric-statistics --namespace SecureFileTransfer/Probe --metric-name ProbeSuccess \
  --dimensions Name=Environment,Value=<env> --statistics Minimum --period 300 \
  --start-time "$(date -u -v-30M +%FT%TZ)" --end-time "$(date -u +%FT%TZ)"
# Every alarm in a known state, none in ALARM
aws cloudwatch describe-alarms --alarm-name-prefix sft-<env>- --state-value ALARM --query 'MetricAlarms[].AlarmName'
```

Osaka's alarms should all be OK or INSUFFICIENT_DATA, and its heartbeat alarm's actions disabled. Each operator
confirms the SNS subscription email for every topic before the environment counts as watched.

## 5. Escalate

An apply that fails halfway leaves its stack's state locked to nothing worse than the resources it made; re-run the
same apply. If a stack can't converge, stop and note it in the issue: don't apply around it by hand.
