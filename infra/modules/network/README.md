# network module

One VPC per account and Region, from the same code in Tokyo and Osaka (T-79): subnets, route tables, the internet and
NAT gateways, the VPC endpoints and their policies, the security groups that make the egress perimeter, Route 53
Resolver DNS Firewall and the VPC flow log ([ADR-0021](../../../docs/adr/0021-network-design-and-egress.md),
[architecture](../../../docs/architecture.md) 3.1 and 3.2). Written by
[#56](https://github.com/codewithmuh/secure-file-transfer/issues/56). Nothing here has been applied (infra/README.md).

| File | Holds |
|---|---|
| `main.tf` | VPC, subnets, route tables, internet gateway, NAT gateways, the default security group and route table (emptied), flow log |
| `endpoints.tf` | The S3 gateway endpoint, the interface endpoints and their policies |
| `security-groups.tf` | Security groups for the endpoints, the cluster API and the three node groups |
| `dns-firewall.tf` | DNS Firewall: the allowlist, the rule group and its association, fail closed |

The egress proxy (Envoy on the `system` nodes) and the cluster itself are not here: the cluster stack builds them on
this module's outputs. This module gives the proxy its path out (the NAT gateways and the `system_nodes` security
group) and the cluster its private API's subnets and security group.

## Address plan

Each VPC is its own /16, IPv4 only. ADR-0021 gave prod's ranges; dev's and staging's follow the same pattern,
10.ER.0.0/16, with E = 1 for dev, 2 for staging, 3 for prod and R = 0 for Tokyo, 1 for Osaka:

| Environment | Tokyo | Osaka |
|---|---|---|
| dev | 10.10.0.0/16 | none |
| staging | 10.20.0.0/16 | 10.21.0.0/16 |
| prod | 10.30.0.0/16 | 10.31.0.0/16 |

AZs are chosen by ID, so every account gets the same physical zones: apne1-az1, -az2 and -az4 in Tokyo (dev: az1 and
az2), apne3-az1 to -az3 in Osaka. Cross-Region PrivateLink can't use apne1-az3, which none of them is. A subnet's range
follows from its AZ number N (az1 is 0), not its place in the list, so adding or removing an AZ moves no other
subnet. For prod in Tokyo:

| Tier | Size | Formula | apne1-az1 | apne1-az2 | apne1-az4 | Route out |
|---|---|---|---|---|---|---|
| public | /24 | 10.x.(128 + N).0 | 10.30.128.0/24 | 10.30.129.0/24 | 10.30.131.0/24 | internet gateway |
| private | /19 | 10.x.(32 × N).0 | 10.30.0.0/19 | 10.30.32.0/19 | 10.30.96.0/19 | NAT gateway; S3 gateway endpoint |
| endpoints | /26 | 10.x.144.(64 × N) | 10.30.144.0/26 | 10.30.144.64/26 | 10.30.144.192/26 | none |
| isolated | /24 | 10.x.(136 + N).0 | 10.30.136.0/24 | 10.30.137.0/24 | 10.30.139.0/24 | none |

The private /19s fill the lower half of the /16 and everything else sits in the upper half, with room for a fourth AZ
in every tier.

## Per environment

| | dev | staging, prod (Tokyo) | staging, prod (Osaka pilot light) |
|---|---|---|---|
| AZs | 2 | 3 | 3 (ADR-0004: failover adds no network step) |
| NAT gateways | 1, in apne1-az1, for both AZs | 1 per AZ | 1 per AZ |
| Interface endpoints | 9, in apne1-az1 only | 10, in every AZ | 10, in every AZ |
| Cross-Region S3 | none (dev is Tokyo only) | S3 in Osaka | S3 in Tokyo |

That is capacity 5's count: in dev 9 endpoint network interfaces (the six of architecture 3.1 and three of ADR-0021),
in staging and prod 30 per Region.

## Endpoints and their policies

Every interface endpoint has private DNS, the `endpoints` security group and a policy built from AWS's data perimeter
pattern. Statement 1 is on every endpoint; the others only where named.

| Key | Service | Policy |
|---|---|---|
| `sqs` | `com.amazonaws.<region>.sqs` | 1, 1a (`sqs:ListQueues`) |
| `kms` | `com.amazonaws.<region>.kms` | 1, 1a (`kms:ListAliases`, `kms:ListKeys`) |
| `secretsmanager` | `com.amazonaws.<region>.secretsmanager` | 1, 1a (`secretsmanager:ListSecrets`) |
| `ecr-api` | `com.amazonaws.<region>.ecr.api` | 1, 1a (`ecr:GetAuthorizationToken`), 2 |
| `ecr-dkr` | `com.amazonaws.<region>.ecr.dkr` | 1, 1a (`ecr:GetAuthorizationToken`), 2 |
| `sts` | `com.amazonaws.<region>.sts` | 1, 1a (`sts:GetCallerIdentity`) |
| `email` | `com.amazonaws.<region>.email` (SES's API) | 1, 1a (`ses:GetAccount`) |
| `ec2` | `com.amazonaws.<region>.ec2` | 1, 1a (`ec2:Describe*`), 3 |
| `eks-auth` | `com.amazonaws.<region>.eks-auth` (EKS Pod Identity) | 1 |
| `s3-peer` | `com.amazonaws.<other region>.s3`, cross-Region | 1 |
| S3 gateway | `com.amazonaws.<region>.s3`, on the private route tables | 1, 4 |

1. **Organization principals to organization resources.** Any action, only when `aws:PrincipalOrgID` and
   `aws:ResourceOrgID` are both our organization. Another account's credentials, bucket, queue or key fails at the
   endpoint (T-53).

   1a. **Calls without a resource.** A request that targets no resource, such as `ecr:GetAuthorizationToken`, may carry
   no `aws:ResourceOrgID`, and `StringEquals` on a missing key is false, so statement 1 alone would deny it: no image
   pull, no node launch. Each endpoint therefore lists its few resourceless read calls (`unscoped_actions` in
   `endpoints.tf`), which our principals may make on the principal check alone. The resource check is not made
   `StringEqualsIfExists`: that would also pass a resource whose account is in no organization, which is what an
   attacker's own bucket or queue looks like. A call missing from a list fails closed, and M4 adds it.
2. **Pulls from AWS-owned registries.** `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` and
   `ecr:BatchCheckLayerAvailability` on the repositories of 602401143452 (EKS add-ons and the pause image) and
   328549459982 (Bottlerocket's host containers), in ap-northeast-1 and ap-northeast-3, for our organization's
   principals. Both IDs are the same in both Regions (EKS user guide, Bottlerocket's registry map, checked
   2026-11-04). A new add-on from another registry is added in `endpoints.tf` and in Kyverno's policy (ADR-0007).
3. **Launches from AWS-owned AMIs.** `ec2:RunInstances` and `ec2:CreateFleet` on images in this Region, for our
   organization's principals, so Karpenter can start Bottlerocket nodes.
4. **ECR's layer bucket.** `s3:GetObject` on `prod-<region>-starport-layer-bucket/*` for any principal. ECR presigns
   each layer URL with its own credentials, so the request's principal is ECR's, not ours, and the statement can't
   name our organization. It stays inside T-53: reads of that one AWS-owned bucket can fetch a layer ECR has
   authorized, but can't write anything out. It serves our registry's layers and the AWS-owned registries' alike.

If AWS reports that a service takes no endpoint policy, the plan fails until its key is in `endpoints_without_policy`,
so an endpoint without a policy is always a recorded decision. The plan reads this from AWS
(`aws_vpc_endpoint_service`), which settles ADR-0021's open question about SES at the first plan in M4.

No statement admits AWS service principals or federated principals, and AWS services don't call through our
endpoints. In particular, the STS endpoint denies `sts:AssumeRoleWithWebIdentity`: the caller of that action is
unauthenticated, so it has no `aws:PrincipalOrgID`. That is by design: workloads get their roles through EKS Pod
Identity, at the `eks-auth` endpoint, never IRSA (ADR-0004). **Anyone adding IRSA, or any other web identity or SAML
federation from inside the VPC, must first add a statement for it to the STS endpoint**, like the
`AllowRequestsToOrgRolesByFederatedPrincipals` statement in AWS's data perimeter examples: federated principals, only
roles in our organization (`aws:ResourceOrgID`).

## Security groups

| Key | Attached to | In | Out |
|---|---|---|---|
| `endpoints` | Interface endpoints | 443 from each private subnet | nothing |
| `cluster_api` | The EKS cluster's network interfaces (additional security group) | 443 from `nodes` | 443 and 1025–65535 to `nodes` |
| `nodes` | Every node | everything from `nodes`; 443 and 1025–65535 from `cluster_api` | (from the pool groups) |
| `system_nodes` | The `system` node group, with `nodes` | (from `nodes`) | the VPC; 443 to anywhere, through NAT |
| `main_nodes` | Karpenter's main pool, with `nodes` | (from `nodes`; the load balancer's rule comes from edge) | the VPC; 443 to S3's prefix list |
| `scan_nodes` | Karpenter's scan pool, with `nodes` | (from `nodes`) | the VPC; 443 to S3's prefix list |

Only the `system` nodes can reach NAT, where the egress proxy and the Systems Manager agent run (ADR-0021). The private
subnets all route to NAT; the security groups decide who may use the route. EKS's own cluster security group allows
all egress, so the cluster stack must keep it off the nodes: a launch template with `nodes` and `system_nodes` for the
`system` group, and Karpenter node classes that select `nodes` and their pool's group by name.

## DNS Firewall

One rule group per VPC, fail closed (`firewall_fail_open = DISABLED`): priority 100 allows the listed names, priority
200 answers NXDOMAIN for `*`. The list is the interface endpoints' own names, S3 in this Region, and
`dns_firewall_allowed_domains`, whose defaults are the design's: the cluster API (`*.<region>.eks.amazonaws.com`), EC2
host names, Cognito (`cognito-idp` and managed login), GitHub, ClamAV's database, the AWS APIs that Karpenter, the
load balancer controller and Alertmanager reach through the proxy, Tokyo's CloudTrail, identity store and STS for the
operator API's break-glass reconciliation (#275), and the Systems Manager agent's names. With
`service_domain` set (every root, from `TF_VAR_domain`), also `api.` and `app.` under it, which the synthetic probe
calls through the egress proxy (#259). The allow
rule trusts CNAME targets (`TRUST_REDIRECTION_DOMAIN`): the owner of an allowed name picks them, a pod can't. The
`dns_firewall_allowed_domains` output shows the complete list for each VPC.

## Flow log

All traffic, Parquet, Hive-compatible hourly partitions, with the fields that show where traffic went behind NAT
(`pkt-dstaddr`, `traffic-path`, `pkt-dst-aws-service`). It goes to the Region's flow log bucket,
`sft-<env>-<region-short>-flow-logs-<account-id>`, which the data layer creates after this one
([`data-stack`](../data-stack/README.md), `flow-logs.tf`): SSE-KMS under the logs key with S3 Bucket Keys, kept 90
days (capacity A19 and A33, encryption 3.1). Its policy and the logs key's let `delivery.logs.amazonaws.com` write
only for this account and Region (`aws:SourceAccount`, `aws:SourceArn`), under `AWSLogs/aws-account-id=<account>/`.
Until `flow_log_destination_arn` is set there is no flow log (`.trivyignore.yaml`, AVD-AWS-0178), so the first build
applies the network twice, the second time with the data root's `flow_log_bucket_arn` output as
`flow_log_destination_arn` (infra/README.md, "Apply order").

## Inputs and outputs

Every variable and output is described in `variables.tf` and `outputs.tf`. The roots pass `name_prefix` and `region`
from the conventions module, and `organization_id` from `aws_organizations_organization`.

## To check against real AWS (M4)

Written from AWS's documentation; only an apply can confirm these.

- Whether `email` (SES) and `eks-auth` take an endpoint policy. The first plan answers it (above).
- That nodes pull add-on images through the ECR endpoints with policy 2, and that Karpenter launches Bottlerocket nodes
  through the EC2 endpoint with policy 3 (an AMI's snapshot may also need statement 3).
- That statement 1a's lists are complete: every resourceless call the nodes, Karpenter, the VPC CNI, the EBS CSI
  driver, External Secrets and the application make through the endpoints. A missing one shows as an AccessDenied
  that names the VPC endpoint in CloudTrail; add it to that endpoint's `unscoped_actions`.
- That the deploy role's tag-conditioned statement (`terraform-oidc-roles`, deletes and `ModifyVpcEndpoint`) doesn't
  block the default security group and route table. It shouldn't: Terraform changes them only with revoke, authorize
  and route actions in the role's untagged statement, scoped to the account's ARNs, and never deletes them. Their
  `tags`, with the provider's default tags, add `managed-by` and `project` on the first apply anyway.
- That the cross-Region S3 endpoint accepts private DNS with `private_dns_only_for_inbound_resolver_endpoint = false`,
  and whether describing cross-Region services needs `vpce:AllowMultiRegion` in the plan role.
- That DNS Firewall's allowlist is complete: run with the rule in `ALERT` instead of `BLOCK` in dev first and read
  the blocked names in the Resolver metrics, then switch to `BLOCK`.
