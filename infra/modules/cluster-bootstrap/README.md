# cluster-bootstrap module

The cluster's platform, installed by Terraform through the Systems Manager tunnel on `main` only
([ADR-0004](../../../docs/adr/0004-compute-eks-karpenter-argo-cd.md), [ADR-0005](../../../docs/adr/0005-terraform-github-actions-argo-cd.md),
[ADR-0021](../../../docs/adr/0021-network-design-and-egress.md)). Argo CD's root Application then installs everything
else from Git. Written by [#104](https://github.com/codewithmuh/secure-file-transfer/issues/104). Nothing here has
been applied (infra/README.md).

| File | Holds |
|---|---|
| `main.tf` | Shared locals (scheduling, proxy listeners, `NO_PROXY`) and the platform namespaces at Pod Security restricted |
| `images.tf` | Every image and chart, pinned by version and digest, pulled from the shared account's ECR (ADR-0007) |
| `egress-proxy.tf` | The egress proxy on the `system` nodes, one listener per workload (ADR-0021) |
| `kyverno.tf` | Kyverno and the `kyverno-policies` chart |
| `karpenter.tf` | Karpenter and its node pools |
| `external-secrets.tf` | External Secrets and its two Secrets Manager stores (`charts/secret-stores`), each assuming its own role: `platform-secrets` (`sft-<env>-external-secrets-platform`, `sft/<env>/platform/*`, platform namespaces) and `application-secrets` (`sft-<env>-external-secrets-app`, the API's secrets, the `sft` namespace only). The controller's own role reads no secret (encryption 6.4) |
| `load-balancer-controller.tf` | The AWS Load Balancer Controller |
| `rbac.tf` | Operator and read-only RBAC for Identity Center roles |
| `argocd.tf` | Argo CD, SAML sign-in through Identity Center, notifications, and the root Application |

## What the acceptance criteria rest on

- **Argo CD syncs only from `main`.** The root Application's `targetRevision` is `main` and its project allows only
  this repository. Auto-sync prunes and self-heals; the local admin and exec are off; Identity Center groups get
  read-only, so nobody changes a source or revision by hand.
- **Kyverno refuses forbidden pod settings.** `charts/kyverno-policies` refuses privileged containers, privilege
  escalation, added capabilities, host namespaces, hostPath and host ports (T-52); images from anywhere but our
  registry or unpinned; unsigned images; `nodeName`; the `system` pool's toleration or node selector outside the
  system namespaces; and namespaces without Pod Security restricted. Only
  `kube-system`, `karpenter`, `kyverno` and `argocd` are outside the webhooks, so a Kyverno outage never blocks what
  brings it back.

## How the stack reaches the cluster

The job that applies a `cluster-bootstrap` root opens a Systems Manager session on a `system` node with the cluster's
tunnel document (modules/eks-cluster, `tunnel.tf`) and passes the local end as `TF_VAR_cluster_api_tunnel_url`; TLS
still checks the cluster's own name. The deploy role may start that session and nothing else there
(`terraform-oidc-roles/permissions-cluster-bootstrap.tf`), and the cluster admits it through the cluster layer's
access entry. The root also reads the cluster layer's outputs and the data layer's `aurora_endpoint`,
`valkey_endpoint` and `kms_key_arns` from their states. That job is not written yet; no workflow opens the tunnel today.

## What the root Application hands the application

The root Application renders `deploy/argocd` with `environment`, `region` and the cluster facts no commit may hold
(#106): the registry host, the database and counter store endpoints, the account ID, the Operator role name, the
files key ARN, the environment's names in the shared zone (`service_domain`, from `TF_VAR_domain`), and, once the user
pool exists, its ID and managed login domain (`cognito_user_pool_id`, `cognito_login_domain`). A null input is left
out, so the application chart's render names what is missing instead of starting pods without it. Kyverno admits the
application's one third-party image, clamd's, by the digest the roots pass in `additional_mirror_digests`, the same as
`deploy/charts/sft/values.yaml` (deploy/tests checks both).

## Tests

`charts/kyverno-policies/tests/run.sh` renders the policies with Helm and runs `kyverno test` from the pinned CLI
image against good and bad pods in `tests/resources.yaml`. It needs Helm and Docker and reaches no cluster.
