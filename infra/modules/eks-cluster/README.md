# eks-cluster module

One EKS cluster per environment and Region, from the same code in Tokyo and Osaka (T-79): the cluster with a private
API only, its control-plane logs, the always-on `system` node group, Karpenter's AWS side, the EKS add-ons, a Pod
Identity role for every workload, the access entries and the Systems Manager tunnel's session document
([ADR-0004](../../../docs/adr/0004-compute-eks-karpenter-argo-cd.md),
[ADR-0021](../../../docs/adr/0021-network-design-and-egress.md), [architecture](../../../docs/architecture.md) 3.1 to
3.3). Written by [#103](https://github.com/codewithmuh/secure-file-transfer/issues/103). Nothing here has been
applied (infra/README.md).

| File | Holds |
|---|---|
| `main.tf` | The cluster and its role, the control-plane log group, the EKS add-ons, the access entries |
| `node-group.tf` | The node roles, the system node group and its launch template |
| `karpenter.tf` | Karpenter's controller policy, its nodes' instance profile and access entry, the interruption queue and its EventBridge rules, and the node classes and node pools as data |
| `workload-roles.tf` | One Pod Identity role per workload and controller, its policy and its associations |
| `tunnel.tf` | The Systems Manager session document that forwards only to the cluster API |

Argo CD, Karpenter, Kyverno and everything else inside the cluster are the cluster-bootstrap layer's
([#104](https://github.com/codewithmuh/secure-file-transfer/issues/104)). Terraform owns no Kubernetes object here:
Karpenter's node classes and node pools are outputs, which cluster-bootstrap applies.

## The cluster

| | |
|---|---|
| Name | `sft-<env>-<region-short>-eks` |
| Version | 1.37 in every root (standard support until December 2027); upgrade policy `STANDARD`, so a cluster never slips into extended support's $365 a month (capacity 7.2) |
| API endpoint | Private only (`endpoint_public_access = false`). Its network interfaces sit in the endpoint subnets with the network's `cluster_api` security group. The deploy role may not create or change a cluster with public access (`eks:endpointPublicAccess`) |
| Authentication | Access entries only (`API`); the creator gets no admin rights |
| Secrets | Envelope encryption with the secrets key (encryption 3.1) |
| Logs | All five control-plane log types, into `/aws/eks/<cluster>/cluster` under the logs key, kept 90 days (A19, A33). The audit log is what break-glass exec alerts read (authn-authz 8.3); SCP 3 keeps logging and the log group with the apply roles |
| Add-ons | VPC CNI with network policies on, kube-proxy, the Pod Identity agent, CoreDNS and the EBS CSI driver, as EKS add-ons at the default version for the cluster's Kubernetes version; `bootstrap_self_managed_addons = false`. CoreDNS and the EBS CSI controller run on the system nodes, so an Osaka pilot light has no pending pod |
| Deletion protection | On in prod |
| Zonal shift | On (NFR-11) |

## Nodes

| Pool | Made by | Instances | Label and taint | Security groups | Volumes |
|---|---|---|---|---|---|
| `system` | EKS managed node group `sft-<env>-<rs>-system` | m8g.large, Bottlerocket arm64; 2 in Tokyo, 1 in an Osaka pilot light (the failover raises it to 2) | `sft.io/pool=system`, `sft.io/pool=system:NoSchedule` | `nodes`, `system_nodes` | 20 GiB data volume, default key (platform) |
| `main` | Karpenter NodePool and EC2NodeClass `main` | m8g.xlarge, on demand | `sft.io/pool=main` | `nodes`, `main_nodes` | 100 GiB (dev 50), default key (platform) |
| `scan` | Karpenter NodePool and EC2NodeClass `scan` | m8g.xlarge, on demand | `sft.io/pool=scan`, `sft.io/pool=scan:NoSchedule` | `nodes`, `scan_nodes` | 50 GiB, files key |

- The launch template and the node classes name the network's groups, so no node carries EKS's own cluster
  security group, which allows all egress.
- IMDSv2 only, hop limit 1 (T-52). Bottlerocket's admin container (a root shell) is off everywhere. Its control
  container, which runs the Systems Manager agent, is on only on system nodes, where the tunnel ends; only the system
  node role may register with Systems Manager.
- Karpenter's NodePools replace nodes after 30 days and on drift (T-52), consolidate after 5 minutes, disrupt at most
  10 % of a pool at once, and stop at a CPU limit per pool: prod 48 and 96 vCPU (12 and 24 nodes), staging 24 and 16,
  dev 16 and 8.
- Karpenter's node classes name the instance profile `sft-<env>-karpenter-node`, not a role, so Karpenter has no IAM
  write permission at all.

## Roles

IAM is global, so each account has one set, created by the **Tokyo** cluster stack (`create_iam = true`); Osaka's
stack refers to them by name, as Osaka's bootstrap stack does for its roles, and so must be applied after Tokyo's.
Each Pod Identity role trusts only `pods.eks.amazonaws.com`, only for the account's clusters (`eks-cluster-arn`) and
only for its own namespace and service account, and its policy covers the resources of every Region with a cluster,
so a failover needs no IAM change. All roles are at path `/`, because the data layer's queue, bucket and key policies
name them exactly (#101, #102), and every one carries the workload permissions boundary (below).

| Role | Namespace / service account | May |
|---|---|---|
| `sft-<env>-api` | `sft` / `api` | Multipart uploads into both files buckets; read size and version; read bytes only of objects tagged `scan=clean` or `scan=unscannable_allowed`; write audit records to the archive in both Regions; its four secrets (each Region's own user pool client); Valkey as `sft-<env>-api`; the database as `sft_api`; files, fields (`field-dek`, `dlp-dek`, and `ReEncrypt` for the field key job, which runs as this role, #236), audit and secrets keys through their services. No delete, no tags, no Cognito |
| `sft-<env>-relay` | `sft` / `relay` | Send to the scan and notify queues; `sft_relay`; platform key through SQS |
| `sft-<env>-scan` | `sft` / `scan-worker` | Read untagged objects in the files bucket; read and write tags in both pairs; consume the scan and GuardDuty result queues; Valkey; `sft_scan`; files key (files bucket only), fields key (`dlp-dek` only), platform key through SQS |
| `sft-<env>-notify` | `sft` / `notifier` | Consume the notify, sign-in events, SES events and tenant status queues; send email through SES; create, delete, disable, read, update and sign out Cognito users and set their temporary password (#193); its three secrets; Valkey; `sft_notify` |
| `sft-<env>-jobs` | `sft` / `jobs` | List, delete object versions and abort uploads in both files bucket pairs, the only role that deletes; `sft_jobs`. No key |
| `sft-<env>-archive` | `sft` / `audit-archive` | Write the audit archive; `sft_archive`; audit key through S3 |
| `sft-<env>-migrate` | `sft` / `migrate` | `sft_migrate` only |
| `sft-<env>-key-rotation` | `sft` / `key-rotation` | Read and write the four keyrings and both Regions' `idp-client`, the secrets key through Secrets Manager for those; add, list and delete the app clients' secrets in Cognito. No database, no other secret (encryption 6.4, #185) |
| `sft-<env>-operator` | `sft-operator` / `operator-api` | Write its audit records to the archive; Valkey as `sft-<env>-operator`, for its rate limits; `sft_operator`; audit key through S3 |
| `sft-<env>-karpenter` | `karpenter` / `karpenter` | Launch, tag and terminate only instances and launch templates tagged with one of the account's cluster names and a node pool; read Bottlerocket's AMI parameters; read the interruption queue; pass only the Karpenter node role; volume keys through EC2 |
| `sft-<env>-lb-controller` | `kube-system` / `aws-load-balancer-controller` | TargetGroupBinding only: describe, and register and deregister targets in the environment's target groups. The edge layer owns the load balancer, its target groups and the security group rule |
| `sft-<env>-external-secrets` | `external-secrets` / `external-secrets` | No secret read: only assume the two store roles below (encryption 6.4) |
| `sft-<env>-external-secrets-platform` | none: assumed by the External Secrets role only | Read `sft/<env>/platform/*`, for the `platform-secrets` store (argocd, monitoring, grafana) |
| `sft-<env>-external-secrets-app` | none: assumed by the External Secrets role only | Read its Region's `idp-client`, for the `application-secrets` store (`sft` only, #106). The API and the notification worker read their keyrings as their own roles (#184) |
| `sft-<env>-kyverno` | `kyverno` / `kyverno-admission-controller`, `kyverno-reports-controller` | Read images and signatures in the organization's `sft/` and `mirror/` repositories; the registry key through ECR |
| `sft-<env>-vpc-cni`, `sft-<env>-ebs-csi` | `kube-system`, through their EKS add-ons | AWS's managed policies for the two drivers; the EBS driver also the platform key through EC2 |
| `sft-<env>-eks-cluster` | (EKS) | `AmazonEKSClusterPolicy`; the secrets key through EKS |
| `sft-<env>-system-node`, `sft-<env>-karpenter-node` | (EC2) | `AmazonEKSWorkerNodePolicy`; image pulls from the organization's registries and the AWS-owned add-on and Bottlerocket registries; the system node role also the Systems Manager agent's calls. The VPC CNI's rights are on its own role, never the nodes' |

KMS statements in the identity policies match the keys by alias (`kms:ResourceAliases`), so no key ID is committed;
the key policies (#102) name the same roles. clamd, the DLP inspector and the signature mirror get no role.

**The workload permissions boundary** `sft-<env>-workload-boundary`, a managed policy under `/sft-bootstrap/` made by
each account's bootstrap stack (`terraform-oidc-roles`, `permissions-cluster.tf`), caps every role above: the
services the cluster and its workloads use, in the environment's Regions; IAM reads, service-linked roles and passing
the Karpenter node role; never an IAM change, and `sts:AssumeRole` only into the two External Secrets store roles. The deploy role may create and change only the roles
named above, only with that boundary, may attach only the four AWS managed policies the module uses, and may never assume
any of them (an explicit deny beats a trust policy that names it), so no apply can mint a role that does more or
borrow a workload's rights.

## Access entries

| Principal | In the cluster |
|---|---|
| Identity Center `ReadOnly` | Kubernetes group `sft:readonly` |
| Identity Center `Operator` | Groups `sft:readonly` and `sft:operator` |
| Identity Center `BreakGlass` | `AmazonEKSClusterAdminPolicy`, cluster-wide |
| `sft-<env>-terraform-deploy` | `AmazonEKSClusterAdminPolicy`, cluster-wide, for the cluster-bootstrap job on `main` |
| `sft-<env>-karpenter-node` | `EC2_LINUX` (the managed node group gets its own from EKS) |

The cluster-bootstrap layer binds the two groups: `sft:readonly` reads workloads, events, logs and Applications
without Secrets and may port-forward only in `grafana`; `sft:operator` may also port-forward in `sft-operator`
(ADR-0004, T-63). Identity Center's roles carry a random suffix, so the module looks them up by name under
`/aws-reserved/sso.amazonaws.com/`; a plan fails unless exactly one matches each permission set.

## The tunnel

`sft-<env>-<rs>-cluster-tunnel` is a Session document of type `Port` that forwards only to the cluster API endpoint
(and any `tunnel_extra_hosts`) on 443. Who may start a session is on the principals: the deploy role's grant is the
cluster-bootstrap layer's (`permissions-cluster-bootstrap.tf`, #104); `ReadOnly`'s and `Operator`'s belong in the
organization stack's permission sets (infra/README.md, "Still to add here"). Each names this document and instances
whose `eks:nodegroup-name` is `sft-<env>-<rs>-system`.

## Karpenter's interruption queue

`sft-<env>-<rs>-karpenter-interruption`, under the platform key, fed by two EventBridge rules,
`sft-<env>-<rs>-karpenter-health` (AWS Health scheduled changes) and `-state-change` (EC2 instance state changes),
through the data layer's execution role `sft-<env>-events-delivery`, the queue's only sender. Both pools are on
demand, so there are no Spot rules.

## Inputs and outputs

Every variable and output is described in `variables.tf` and `outputs.tf`. The roots read the network layer's outputs
from its state (`terraform_remote_state`, the same state bucket) and the organization ID from
`aws_organizations_organization`, and look the keys up by alias.

## To check against real AWS (M4)

Written from AWS's documentation; only an apply can confirm these.

- That EventBridge delivers to the interruption queue through the execution role, with the platform key's statement
  for that role (#102).
- That the VPC CNI and EBS CSI add-ons start with Pod Identity before the nodes have other pods, and that the add-on
  configuration keys (`enableNetworkPolicy`, `controller.tolerations`, CoreDNS's `nodeSelector`) are accepted for the
  default versions.
- That the deploy role's permissions are complete for `CreateNodegroup` with a launch template, and that
  `eks:endpointPublicAccess` is present on `CreateCluster` and `UpdateClusterConfig` as AWS announced in April 2026.
- That the Kyverno, node and Karpenter statements that match on `aws:ResourceOrgID` pass for the shared registry's
  repositories and its key.
- That the system node group's 2 × m8g.large hold the platform (capacity 4.2 measures it at the first build).
