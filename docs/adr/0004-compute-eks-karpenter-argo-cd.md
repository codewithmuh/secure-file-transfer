# 0004. Use EKS with Karpenter and Argo CD for compute

- Status: accepted
- Date: 2026-11-03
- Issue: [#31](https://github.com/codewithmuh/secure-file-transfer/issues/31)

## Context

What the compute platform has to carry ([architecture](../architecture.md) sections 2, 3 and 7,
[capacity](../design/capacity-and-cost.md) section 4):

- **One codebase, several workloads.** The API service, outbox relay, scan and notification workers and lifecycle jobs
  come from one image with different entry points. The operator API is its own Deployment in the `sft-operator`
  namespace ([authn-authz](../security/authn-authz.md) 8.2).
- **Shapes that change.** The API runs 3 to 15 pods, scaled on request rate, CPU and active download streams, because
  downloads stream through it ([abuse](../security/abuse-and-rate-limits.md) 5.7). Scan pods run one per node on
  their own node pool, 5 to about 20 nodes on queue age ([encryption](../security/encryption-and-keys.md) 3.1).
- **Isolation inside the cluster.** One IAM role per workload, default-deny network policies, Pod Security Admission
  at `restricted`, and no shell or tunnel into application pods for normal operators
  ([threat model](../threat-model.md) T-51, T-52, T-63).
- **Recovery.** An AZ loss recovers in ≤ 5 minutes (NFR-11). In a regional failover, "add worker nodes in Osaka; Argo
  CD deploys" has 20 of the 55 minutes (architecture 7). Osaka is a pilot light: compute starts only on failover.
- **Delivery and teardown.** Zero-downtime deploys and rollback ≤ 10 minutes (NFR-18); rebuild ≤ 2 hours and teardown
  ≤ 1 hour (NFR-19).
- **Cost.** Worker nodes are prod's largest idle cost, $1,100 of $3,036 a month; each control plane costs $73, and
  extended support would add $365 a month per cluster (capacity 7.1, 7.2).

## Decision

Run every workload on **Amazon EKS**, one cluster per environment and region: dev in Tokyo, staging and prod in Tokyo
and Osaka. **Karpenter** provisions the two node pools of capacity 4.2: main (m8g.xlarge) and scan (m8g.large, tainted,
one scan pod per node), across 3 AZs. Karpenter itself, CoreDNS and Argo CD run on a small EKS managed node group,
`system`, so nothing Karpenter depends on runs on nodes it manages. **Argo CD** in each cluster deploys from Git
([ADR-0005](0005-terraform-github-actions-argo-cd.md)). KEDA scales workers on queue age and the API on active streams;
EKS Pod Identity gives each workload its own IAM role.

The **Osaka pilot light** is the control plane, Argo CD installed, and the `system` group at zero nodes. A failover
scales `system` to two nodes; Argo CD and Karpenter start, Karpenter adds main and scan nodes, and Argo CD deploys what
Git holds for Osaka, with every worker at zero (architecture 7). The Osaka network stays in three AZs.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **EKS with Karpenter and Argo CD** (chosen) | Karpenter launches the right node for each pending pod, consolidates idle nodes, and replaces a lost AZ's nodes within minutes (capacity 4.2). Tainted pools keep hostile files on their own nodes. Network policies, Pod Security Admission, Pod Identity and RBAC give the operator rules of authn-authz 8.1 one model. Argo CD makes Git the deployed state, which rollback (NFR-18) and failover fencing (T-78) rely on. The same manifests run in every environment. | The most parts to run: the cluster, Karpenter, Argo CD, KEDA, the Load Balancer Controller, External Secrets and an admission controller ([ADR-0007](0007-container-registry-ecr.md)) are ours to upgrade, and EKS must move a minor version at least yearly to stay off extended support. Karpenter can't run on nodes it manages, so the `system` group adds about $169 a month in prod Tokyo (2 × m8g.large) and $85 in dev and in staging (2 × m8g.medium) while they run, not yet in the capacity model. Five control planes at $73 each. Deploys cut long downloads, which resume (abuse 5.7). |
| **ECS on Fargate** | No cluster, nodes or node OS to run. Each task is its own micro-VM, which suits the scan engine. Services at desired count zero make a pilot light with no control plane to pay for. Fewest parts for one maintainer. | No GitOps controller: deploys, rollbacks and fencing a returning Tokyo (T-78) become pipeline or API steps rather than Git changes. No network policies or Pod Security Admission; security groups per task instead. No DaemonSets, so log and telemetry agents become sidecars in every task. Leaves the candidate stack (architecture 9). |
| **EKS with managed node groups only** | AWS replaces and upgrades nodes. No Karpenter; Cluster Autoscaler can scale a group from zero. | Still needs Cluster Autoscaler. Each group is an Auto Scaling group with a fixed list of instance types; it scales out more slowly than Karpenter launches nodes and doesn't consolidate, so packing drifts from capacity 4.2, and the scan pool's swings from 5 to 20 nodes take longer. |
| **EKS Auto Mode** | The strongest alternative. AWS runs Karpenter, the VPC CNI, storage and load balancer controllers off the nodes, and patches and replaces nodes. A cluster can sit at zero nodes and start them for the first pending pod, with no `system` group. | A management fee on every node on top of the EC2 price, on the largest idle cost line. AWS picks the node OS and the core component versions. Less of the platform is ours to show and test, the same trade ADR-0002 made for the framework. |

## Consequences

- **Bootstrap.** Terraform creates the cluster, the `system` group, access entries, Pod Identity associations and the
  Argo CD release. Argo CD installs everything else from Git, Karpenter first (sync waves). Terraform owns no other
  Kubernetes object.
- **The Osaka step.** Scale `system` from 0 to 2 in the Osaka cluster's Terraform (ADR-0005). Karpenter then pulls
  images from the Osaka registry replica (ADR-0007) and launches nodes; nothing waits on Tokyo. The 20-minute budget is
  unmeasured until the first staging drill. Keeping the Osaka network in three AZs costs about $220 a month more than
  one (capacity 7.2), but failover adds no network step and lands multi-AZ.
- **Operator access** (authn-authz 8.1, T-63). EKS access entries, not the `aws-auth` ConfigMap, map each IAM Identity
  Center permission set ([ADR-0006](0006-aws-account-per-environment.md)) to a Kubernetes group:

| Permission set | In the cluster |
|---|---|
| `ReadOnly` | Read workloads, events and logs; no Secrets, exec, attach or port-forward |
| `Operator` | `ReadOnly`, plus `pods/portforward` only in `sft-operator`, and listing and syncing Argo CD Applications through the Argo CD CLI's core mode. A validating admission policy lets this group change only an Application's sync operation, never its source, revision or parameters. |
| `BreakGlass` | Cluster admin. Every exec, attach or port-forward into an application pod alerts from the audit log. |
| Terraform apply role | Cluster admin, which installing Argo CD needs. No person applies manifests; changes go through Git. |

- **Hardening.** Default-deny network policies through the VPC CNI, Pod Security Admission at `restricted`, IMDSv2 with
  a hop limit of 1, and Bottlerocket nodes that Karpenter replaces on a schedule (T-52). The cluster API endpoint is
  public but accepts only IAM principals mapped by access entries, so operators and GitHub-hosted runners reach it
  without a VPN; nodes use the private endpoint. Limiting its source addresses is an open point for the threat model.
- **Upgrades.** One EKS minor version at a time within standard support: staging first, each Osaka cluster with its
  Tokyo cluster, so the pilot light never falls behind (T-79).
- **Capacity model.** The `system` group raises the operating month by about $220 (prod 24×7, dev and staging at their
  expected hours), to about $4,300 against the $6,000 budget. Argo CD, Karpenter and CoreDNS leave the main pool, which
  keeps its node counts at idle and in the peak hour.

When to revisit: after the first two vertical slices, if cluster and add-on upgrades take more than a day a month of
the maintainer's time, or if the first staging drill misses the 20-minute step. EKS Auto Mode is the first fallback;
ECS on Fargate if Kubernetes itself is the burden.
