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
  CD deploys" has 20 of the 57 minutes (architecture 7). Osaka is a pilot light: its application compute starts only
  on failover.
- **Delivery and teardown.** Zero-downtime deploys and rollback ≤ 10 minutes (NFR-18); rebuild ≤ 2 hours and teardown
  ≤ 1 hour (NFR-19).
- **Cost.** Nodes are prod's largest idle cost, over a third of its $3,567 a month; each control plane costs $73, and
  extended support would add $365 a month per cluster (capacity 7.1, 7.2).

## Decision

Run every workload on **Amazon EKS**, one cluster per environment and region: dev in Tokyo, staging and prod in Tokyo
and Osaka. **Karpenter** provisions the two node pools of capacity 4.2: main (m8g.xlarge) and scan (m8g.large, tainted,
one scan pod per node), across 3 AZs. The cluster's own platform runs on a small, tainted EKS managed node group,
`system`, two m8g.large in each Tokyo cluster: Karpenter, CoreDNS, Argo CD, the admission controller Kyverno
([ADR-0007](0007-container-registry-ecr.md)) and the egress proxy ([ADR-0021](0021-network-design-and-egress.md)), so
nothing that Karpenter or admission depends on runs on nodes Karpenter manages. **Argo CD** in each cluster deploys
from Git ([ADR-0005](0005-terraform-github-actions-argo-cd.md)). **KEDA** owns all workload autoscaling, one
ScaledObject per Deployment: the API on CPU, request rate and active streams, the workers on queue age. EKS Pod
Identity gives each workload its own IAM role.

The **Osaka pilot light** is the control plane and one `system` node that stays on, running Argo CD, Kyverno,
Karpenter, CoreDNS and the proxy at one replica each, so the cluster stays installed, upgraded and in sync with Git.
Osaka's values in Git hold it in pilot-light mode: every application workload at zero replicas and no observability
stack, so no pod is pending and Karpenter launches no node. A failover scales `system` from one node to two, and the
fencing commit takes Osaka out of pilot-light mode; Karpenter adds main and scan nodes, and Argo CD deploys what Git
holds for Osaka, with every worker at zero (architecture 7). The Osaka network stays in three AZs.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **EKS with Karpenter and Argo CD** (chosen) | Karpenter launches the right node for each pending pod, consolidates idle nodes, and replaces a lost AZ's nodes within minutes (capacity 4.2). Tainted pools keep hostile files on their own nodes. Network policies, Pod Security Admission, Pod Identity and RBAC give the operator rules of authn-authz 8.1 one model. Argo CD makes Git the deployed state, which rollback (NFR-18) and failover fencing (T-78) rely on. The same manifests run in every environment. | The most parts to run: the cluster, Karpenter, Argo CD, KEDA, the Load Balancer Controller, External Secrets, Kyverno and the egress proxy are ours to upgrade, and EKS must move a minor version at least yearly to stay off extended support. Karpenter can't run on nodes it manages, so the `system` group costs two m8g.large in each Tokyo cluster ($169 a month while it runs) and one in each Osaka cluster ($85). Five control planes at $73 each. Deploys cut long downloads, which resume (abuse 5.7). |
| **ECS on Fargate** | No cluster, nodes or node OS to run. Each task is its own micro-VM, which suits the scan engine. Services at desired count zero make a pilot light with no control plane to pay for. Fewest parts for one maintainer. | No GitOps controller: deploys, rollbacks and fencing a returning Tokyo (T-78) become pipeline or API steps rather than Git changes. No network policies or Pod Security Admission; security groups per task instead. No DaemonSets, so log and telemetry agents become sidecars in every task. Leaves the stack of architecture 9. |
| **EKS with managed node groups only** | AWS replaces and upgrades nodes. No Karpenter; Cluster Autoscaler can scale a group from zero. | Still needs Cluster Autoscaler. Each group is an Auto Scaling group with a fixed list of instance types; it scales out more slowly than Karpenter launches nodes and doesn't consolidate, so packing drifts from capacity 4.2, and the scan pool's swings from 5 to 20 nodes take longer. |
| **EKS Auto Mode** | The strongest alternative. AWS runs Karpenter, the VPC CNI, storage and load balancer controllers off the nodes, and patches and replaces nodes. A cluster can sit at zero nodes and start them for the first pending pod, with no `system` group. | A management fee on every node on top of the EC2 price, on the largest idle cost line. AWS picks the node OS and the core component versions. Less of the platform is ours to show and test, the same trade ADR-0002 made for the framework. |

## Consequences

- **Bootstrap.** Terraform creates the cluster, the `system` group, access entries and Pod Identity associations, and,
  in a `cluster-bootstrap` root module applied through the Systems Manager tunnel (ADR-0021), the Argo CD release.
  Argo CD installs everything else from Git in sync waves, Karpenter and Kyverno first. Terraform owns no other
  Kubernetes object.
- **No admission deadlock.** Kyverno runs on the `system` group, which exists before Karpenter does. Its blocking
  webhooks exclude the `kube-system`, `karpenter`, `kyverno` and `argocd` namespaces, whose images are pinned by digest
  in Git and checked against the same policies by the Kyverno CLI in CI (ADR-0007). A cold start, a replaced `system`
  node or a Kyverno outage therefore never blocks the components that bring Kyverno back; every other namespace fails
  closed while it is down.
- **The Osaka step.** Scale `system` from one node to two in the Osaka cluster's Terraform (ADR-0005), and merge the
  fencing commit, which also takes Osaka out of pilot-light mode. Karpenter then pulls images from the Osaka registry
  replica (ADR-0007) and launches nodes; nothing waits on Tokyo. The 20-minute budget is unmeasured until the first
  staging drill. Keeping the Osaka network in three AZs costs about $300 a month more than one (capacity 7.2), but
  failover adds no network step and lands multi-AZ.
- **Scaling.** Each autoscaled Deployment has one ScaledObject, and the HPA that KEDA creates from it is the only one
  on that Deployment, so no two autoscalers fight. The API's has three triggers, CPU, request rate and active download
  streams (50 per pod, architecture 2), between 3 and 15 pods; if Prometheus can't be read, the CPU trigger still
  works.
- **EKS add-ons.** The VPC CNI, kube-proxy, CoreDNS, the Pod Identity agent and the EBS CSI driver are EKS add-ons.
  Their images and the pause image come from the AWS-owned EKS and Bottlerocket registry accounts for ap-northeast-1
  and ap-northeast-3, which the endpoint policies (ADR-0021) and Kyverno's image policy (ADR-0007) allow by registry
  and repository; everything else comes from our registry.
- **Operator access** (authn-authz 8.1, T-63). EKS access entries, not the `aws-auth` ConfigMap, map each IAM Identity
  Center permission set ([ADR-0006](0006-aws-account-per-environment.md)) to a Kubernetes group:

| Permission set | In the cluster |
|---|---|
| `ReadOnly` | Read workloads, events, logs and Argo CD Applications; `pods/portforward` only in `grafana`, Grafana's namespace (ADR-0009). No Secrets, exec, attach or other port-forward. |
| `Operator` | `ReadOnly`, plus `pods/portforward` in `sft-operator`. It changes no Application and no workload: syncs come only from Git. |
| `BreakGlass` | Cluster admin. Every exec, attach or port-forward into an application pod alerts from the audit log. |
| Terraform apply role | Cluster admin, which installing Argo CD needs, used only by the `cluster-bootstrap` job on `main`. No person applies manifests; changes go through Git. |

- **Argo CD** runs in normal mode, not core mode. Its API server signs people in through Identity Center (SSO) and
  gives `ReadOnly` and `Operator` read-only RBAC, so nobody can change an Application's source, revision, parameters
  or sync operation, and no operator needs access to Secrets in `argocd`. They reach it through the same Systems
  Manager tunnel as the cluster API (ADR-0021). Auto-sync with self-heal applies Git; a stuck sync is fixed by a
  commit.
- **Hardening.** Default-deny network policies through the VPC CNI, with what each workload may reach listed in
  ADR-0021; Pod Security Admission at `restricted`; IMDSv2 with a hop limit of 1; and Bottlerocket nodes that Karpenter
  replaces on a schedule (T-52). The cluster API endpoint is private only (ADR-0021): people reach it through a Systems
  Manager port-forwarding session to a `system` node, and so does GitHub Actions, with no runner in the VPC: the
  `cluster-bootstrap` job on a GitHub-hosted runner starts that session with the apply role. Nodes use the private
  endpoint directly.
- **Upgrades.** One EKS minor version at a time within standard support: staging first, each Osaka cluster with its
  Tokyo cluster, so the pilot light never falls behind (T-79). The always-on Osaka `system` node is what lets
  Terraform and Argo CD upgrade Osaka's platform along with Tokyo's.
- **Capacity model.** Capacity 4.2, 4.3 and 7 carry the `system` groups: two m8g.large in each Tokyo cluster, dev and
  staging included, because Kyverno and the proxy don't fit two m8g.medium, and one in each Osaka cluster. With them
  and ADR-0021's lines the planned operating month is about $4,770 against the $6,500 budget (73 %)
  (capacity 7.3). Argo CD, Karpenter, CoreDNS and Kyverno leave the main pool, which keeps its node counts at idle and
  in the peak hour.

When to revisit: after the first two vertical slices, if cluster and add-on upgrades take more than a day a month of
the maintainer's time, or if the first staging drill misses the 20-minute step. EKS Auto Mode is the first fallback;
ECS on Fargate if Kubernetes itself is the burden.
