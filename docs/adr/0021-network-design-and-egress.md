# 0021. Keep clusters private and send egress through VPC endpoints or an allowlisting proxy

- Status: accepted
- Date: 2026-11-03
- Issue: [#35](https://github.com/codewithmuh/secure-file-transfer/issues/35)

## Context

- **Where phase 2 started.** A VPC across 3 AZs with public, private and isolated subnets, endpoints for S3, SQS, KMS,
  Secrets Manager, ECR and STS, and SES and the Osaka writes through NAT. [Architecture](../architecture.md) 3.1 and
  3.2 now follow this ADR. Osaka keeps its whole network in 3 AZs ([ADR-0004](0004-compute-eks-karpenter-argo-cd.md)).
- **Egress is how data leaves.** In the [threat model](../threat-model.md), T-53 is code in a compromised pod sending
  data out through NAT, or through an endpoint to another account. Network policies allowed the NAT flows only by
  address, and the names they need are shared by every AWS customer, so the path stayed open: R-15, until this ADR.
- **What still needs the internet.** Cognito (token endpoint, signing keys, admin calls): a user pool with a domain
  can't use PrivateLink, and the sign-in web ACL takes code exchanges only from our NAT addresses
  ([abuse](../security/abuse-and-rate-limits.md) 3.2). GitHub for Argo CD, ClamAV's database for the signature mirror,
  some AWS APIs for platform controllers and alerting. Since late 2025 SES's API has interface endpoints and
  PrivateLink reaches S3 in another region, so SES and the Osaka calls no longer need NAT.
- **The cluster API.** The starting point was a public endpoint for IAM principals mapped by access entries, its
  source addresses an open point. Operators use it ([authn-authz](../security/authn-authz.md) 8.1); CI needs it only
  for Terraform's Argo CD release ([ADR-0005](0005-terraform-github-actions-argo-cd.md)), from GitHub-hosted runners,
  which have no fixed addresses for a personal repository. Argo CD, Karpenter and the nodes run inside.
- **Cost** ([capacity](../design/capacity-and-cost.md) 5 and 7, prices of 2026-11-03). NAT, interface endpoints and
  public IPv4 are prod's third-largest idle cost (capacity 7.1); an interface endpoint is $0.014 an hour per AZ. AWS
  Network Firewall is $0.395 per endpoint-hour and $0.065/GB in both regions, its NAT gateway's charges waived; TLS
  inspection adds $1.095 an hour.

## Decision

- **VPCs.** One per account and region, IPv4 only, each its own /16 (prod: 10.30.0.0/16 Tokyo, 10.31.0.0/16 Osaka).
  Three AZs by ID (apne1-az1, -az2, -az4; apne3-az1 to -az3); dev uses two, with one NAT gateway and endpoints in one
  AZ (capacity 5.3). Per AZ: a public /24 (load balancer, NAT gateway), a private /19 (nodes, pods, Cognito trigger
  functions), an endpoint /26 that holds only the interface endpoints and the cluster API's network interfaces, and an
  isolated /24 (Aurora, Valkey) with no route out. The load balancer is IPv4-only (abuse 2.1).
- **Endpoints.** Keep the S3 gateway and six interface endpoints and add four: SES's API (`email`), EC2 and EKS Auth
  (so main and scan nodes need nothing outside the VPC), and S3 in the other region. Interface endpoint policies allow
  only principals in our organization (`aws:PrincipalOrgID`) and, where supported, resources in our accounts. The ECR
  endpoints (`api`, `dkr`) also allow the AWS-owned EKS and Bottlerocket registry accounts for ap-northeast-1 and
  ap-northeast-3, which serve the EKS add-ons, the pause image and Bottlerocket's host containers (ADR-0004,
  [ADR-0007](0007-container-registry-ecr.md)). The S3 gateway's policy allows our buckets and the AWS-owned bucket that
  serves ECR image layers, for our registry and those registries alike; the cross-region one only our buckets there.
- **Egress: an allowlisting proxy, not Network Firewall.** Envoy as an HTTPS `CONNECT` proxy on the `system` nodes:
  two replicas in different AZs in each Tokyo cluster and one in an Osaka pilot light (two after a failover), each
  requesting 0.1 vCPU and 0.25 GiB, which ADR-0004 sizes the `system` group for. One listener and allowlist per
  workload: the API (our managed login domain, `cognito-idp.ap-northeast-1.amazonaws.com`), the notification worker
  (Cognito's API), Argo CD (`github.com`, `api.github.com`, for Git and its notifications), the signature mirror
  (`database.clamav.net`), and the platform: controllers, Kyverno and the observability stack, for AWS APIs with no
  endpoint here (such as SNS and CloudWatch for alerts, [ADR-0009](0009-observability-opentelemetry-self-hosted.md))
  and ECR's layer bucket for Kyverno's signature reads. No pod but the proxy reaches the NAT gateways (one per AZ).
  Route 53 Resolver DNS Firewall answers only allowed names and fails closed.
- **Network policies, per workload.** Default deny, and never the whole VPC: each workload may reach CoreDNS, its own
  proxy listener, the endpoint subnets on 443, and only the data stores it uses on their ports, Aurora on 5432 and
  Valkey on 6379, the latter for the API, the scan worker (scan leases) and the notification worker (cross-tenant
  per-address caps), while the sign-in triggers reach Valkey by security group. In-cluster flows (Prometheus scrapes,
  the operator API, the cluster API for controllers) are named one by one, so a pod reaches no other workload without a
  rule. S3 in its own region uses public addresses through the gateway endpoint, and a network policy can't name S3's
  prefix list, so the pods that use it (the API, the scan worker, the lifecycle jobs, Loki and Tempo) may reach
  addresses outside the VPC on 443, and the main and scan nodes' security groups, which can name a prefix list, allow
  nothing outside the VPC but S3's. Application pods can't run on `system` nodes (they're tainted, and Kyverno refuses
  the toleration in application namespaces), and pods there, whose security group must let the proxy reach NAT, get no
  outside rule: they use the endpoints, or the proxy, which reaches S3 through the gateway endpoint.
- **Cluster API: private only.** Public access is off. People and CI reach the endpoint by Systems Manager port
  forwarding to a `system` node, through our session document, which forwards only to the cluster endpoint and to the
  Argo CD API server (ADR-0004), on 443. GitHub Actions runs no runner in the VPC: the `cluster-bootstrap` job on a
  GitHub-hosted runner starts that session with the apply role. `ReadOnly`, `Operator` and the apply role may start no
  other session, and access entries and Argo CD's RBAC still decide what each may do. Every cluster, Osaka's pilot
  light included, keeps a `system` node running, so the tunnel always has an end. Only Terraform's Argo CD release
  needs a tunnel from CI. Argo CD polls GitHub through the proxy: no webhook, no inbound path.
- **DNS.** The shared account ([ADR-0006](0006-aws-account-per-environment.md)) holds the public zone `sft.<domain>`,
  delegated once from the maintainer's domain (PRD open question 5) and DNSSEC-signed (T-01). It delegates nothing:
  dev's, staging's and prod's records all live in it, each written by that environment's apply role through a narrow
  cross-account DNS role that may change only that environment's names. There are no per-environment zones, so a
  torn-down environment leaves records to delete, never a delegation to a deleted zone. API records alias the Tokyo
  load balancer, and the failover runbook moves the alias (T-78).
- **Health checks.** Each load balancer checks its targets' `GET /readyz` on a target port that the public listener
  doesn't route; the API has no public health route. Two Route 53 HTTPS health checks with string matching (A32), for
  alarms only, probe a fixed response that each region's load balancer answers itself, with no targets: they show
  whether a region's edge answers, and Osaka's passes during the pilot light instead of always failing. API health
  comes from the load balancers' target health and the synthetic probe.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **VPC: one per account and region** (chosen) | Each environment builds and tears down its own network (NFR-19); Tokyo and Osaka come from one module (T-79); separate ranges keep peering possible. | Five sets of NAT gateways and endpoints, the largest fixed network cost (capacity 7.1). |
| **VPC: a network account sharing subnets with each environment** | One set of NAT gateways and endpoints per region for all environments. | dev and staging would share a network, NAT addresses and DNS Firewall with prod; teardown crosses accounts; one more account to run. |
| **Endpoints: org-pinned policies, plus SES, EC2, EKS Auth and cross-region S3** (chosen) | Sends, download grants, Osaka deletes and the nodes depend on neither NAT nor the proxy; another account's credentials or buckets fail at the endpoint. | $245 a month more in prod. Cross-region PrivateLink is new: it can't use apne1-az3, needs `vpce:AllowMultiRegion` in IAM and the SCPs, and has only regional DNS. Whether SES's endpoint takes a policy is checked in the first network slice. The AWS-owned registries must be named per region, and a new add-on needs its registry added. |
| **Endpoints: the six of architecture 3.1, default policies; SES and Osaka through NAT** | No extra endpoint charges. | The API needs a path to S3 in Osaka and the notification worker to SES, names every AWS customer shares; a default policy lets a pod use an endpoint with another account's credentials. |
| **Egress: proxy with per-workload allowlists** (chosen) | The proxy resolves each name itself, so a pod can't name an allowed host and connect elsewhere; each workload reaches only its own names and no address directly; logs show bytes per workload and name. Small enough to share the `system` nodes. | Ours to run, on the sign-in path: if every replica fails, code exchanges, Cognito admin calls, Argo CD syncs and in-cluster alert delivery stop (sends, downloads and Osaka writes don't; the heartbeat alarm pages). Every client must honour `HTTPS_PROXY`. It can't see inside TLS, so an allowed shared name still reaches an attacker's own account there. Host processes on `system` nodes, the Systems Manager agent among them, reach NAT without it; Bottlerocket runs no others, and DNS Firewall still limits their names. |
| **Egress: AWS Network Firewall with a domain allowlist** | Managed and transparent: no client settings; endpoints per AZ scale on their own; stateful rules and logs in one place. | About $1,870 a month net of the NAT waiver (prod $1,459, staging $324, dev $87), taking the planned month past the $6,000 budget. It matches the SNI the client sends, so code in a pod can name an allowed host and connect to any address; only TLS inspection closes that, about $4,800 a month more in prod. One allowlist for the whole VPC. |
| **Egress: security groups, network policies, NAT and DNS Firewall only** | Nothing more to run or pay for; the threat model's baseline. | Policies match addresses, and Cognito's and SES's are AWS's shared ranges, so a pod reaches any AWS-hosted address, or any address through NAT; R-15 stays as written. |
| **Cluster API: private only, through Systems Manager** (chosen) | No API server on the internet. One path for people and CI, decided by IAM and logged by CloudTrail. Trivy's EKS public-access checks pass without an exception. | Every `kubectl` session needs a tunnel and a kubeconfig with `tls-server-name`; a tunnel in a CI job is one more thing to fail; no access while the `system` nodes are down (an apply can then allow one address publicly, which alerts; the SCP keeps endpoint changes with the apply roles, ADR-0006); the agent on `system` nodes is a path IAM must keep to one document. |
| **Cluster API: public for listed addresses, plus private** | `kubectl` works directly from listed addresses. | GitHub-hosted runners for a personal repository have no fixed addresses (static ones need larger runners in a paid GitHub organization), so CI still needs another way in; the maintainer's address changes, and each change is an apply that takes minutes, an emergency included. |
| **Cluster API: public and private, IAM only** (the starting point) | Works from anywhere, CI included, with no tunnel or list. | The API server faces the internet, so a flaw before authentication, or a stolen session, is usable from anywhere; Trivy's checks need a recorded exception. |
| **DNS: one zone in shared, every environment's records in it** (chosen) | Delegated once and outlives every environment, so no delegation ever points at a torn-down zone (T-01). | Each environment writes records into another account's zone through a role limited by record name; a teardown must delete its records, which a check confirms. |
| **DNS: the shared zone delegating `dev.` and `staging.` to their accounts** | Each account owns its own zone. | Each teardown deletes a zone that shared still delegates to, a dangling delegation that someone else could claim (T-01), unless every teardown also edits shared. |
| **DNS: a zone per environment, each delegated from the parent** | Each account owns all its records. | Three delegations at the maintainer's DNS host to keep in step with teardowns, each a dangling-record risk (T-01); dev and staging names fall outside the subdomain. |
| **DNS: failover records that switch on health checks** | Failover without a person. | A failing check, real or forced, moves traffic to a region with no compute and before security-critical changes are re-applied (T-77, T-78). |

## Consequences

- **Cost.** The new endpoints add $245 a month in prod (12 interfaces per region), $54 in staging at its 162 hours and
  $11 in dev (three, one AZ); DNS Firewall about $2 at idle and $12 at design load ($0.60 per million queries, 3 M and
  20 M assumed). Capacity 5 and 7.3 carry them: with ADR-0004's `system` groups, the planned operating month is about
  $4,770, 73 % of the $6,500 budget the maintainer set for the operating period (capacity 7.3).
- **Threat model.** T-53 points here, residual Low: no pod leaves the VPC but through its listener or to S3 through
  the gateway endpoint, Osaka calls and SES use endpoints, DNS Firewall stops DNS tunnelling. R-15 narrows to shared
  names a workload must reach: via Cognito's API the API or notification pod can write to another account's user pool,
  and Argo CD can reach any GitHub repository; a proxy byte alert detects it.
- **Other documents.** Architecture 3.1, encryption 2.2 and 2.3, TB-3, TB-9 and capacity A17 follow this ADR: SES and
  the Osaka calls left NAT, and everything else outbound goes through the proxy. ADR-0004 keeps the cluster endpoint
  private; ADR-0006's SCPs allow `vpce:AllowMultiRegion`, and its us-east-1 exceptions include DNSSEC's signing key in
  KMS and the alarms on health-check metrics, which exist only there.
- **Clients and Terraform.** botocore, httpx, Argo CD, Kyverno, freshclam and the controllers' Go SDK honour
  `HTTPS_PROXY`; `NO_PROXY` lists endpoint names and cluster services; Karpenter runs in isolated-VPC mode. Argo CD's
  release is in a `cluster-bootstrap` root module, planned and applied only on `main` in the job that opens the
  tunnel, so pull request plans never reach the cluster API; `make kube` opens a tunnel and writes the kubeconfig.
- **Failover** needs no tunnel: its steps are AWS API calls and Git changes (ADR-0004, ADR-0005), and moving the
  alias is a Route 53 control-plane call, independent of Tokyo.
- **Checks.** In staging, a direct address, a name outside its list, another workload's listener, another workload's
  pods or data store, and another account's bucket through each S3 endpoint all fail from an application pod (threat
  model section 6). AWS Config's `eks-endpoint-no-public-access` rule and Trivy catch a public endpoint. A teardown
  check fails if the environment's records remain in the shared zone; the final teardown removes the parent's
  delegation before the shared zone, so no name server record points at a deleted zone (T-01).

When to revisit: if Cognito accepts PrivateLink for a pool with a domain (the API and notification worker then leave
the proxy); if TLS inspection becomes affordable or real customer data arrives, which would justify Network Firewall
with inspection; if the proxy causes a sign-in incident; or if tunnels cost the maintainer real time.
