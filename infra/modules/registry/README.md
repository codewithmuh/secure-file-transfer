# registry module

The container registry in the shared account ([ADR-0007](../../../docs/adr/0007-container-registry-ecr.md),
[encryption](../../../docs/security/encryption-and-keys.md) 3.1 and 4.4, capacity 5.4). Written by
[#105](https://github.com/codewithmuh/secure-file-transfer/issues/105). Nothing here has been applied (infra/README.md).

| Piece | What it does |
|---|---|
| Registry key | `alias/sft/shared/registry`, multi-Region, rotated yearly. Administered by the shared deploy role; used by ECR (grants), the push role and the environments' node and Kyverno roles, all only through ECR |
| Repositories | `sft/app` and `mirror/<name>` for each `mirror_repositories` entry. Immutable tags except cosign's `sha256-*` fallback tags; KMS encryption with the registry key; basic scanning on push |
| Pull policy | `sft-<env>-system-node` and `sft-<env>-karpenter-node` in each member account pull; `sft-<env>-kyverno` also lists and describes images to read signatures (#103, #104). The principals are the accounts, narrowed by `aws:PrincipalArn`, because ECR refuses a policy naming a role that doesn't exist yet |
| Lifecycle | `sft/app`: every `deployed-*` image kept, and every cosign `sha256-*` fallback signature or attestation; tagged builds beyond the newest 30 expire (A40). No rule selects untagged images, so cosign's untagged OCI referrer signatures of kept images can't expire (ECR expires a referrer only with its subject); a build that failed its scan stays untagged until deleted by hand. Mirrors keep everything |
| Push role | `sft-shared-image-push` under `/sft-shared/`, trusted only by jobs in the `registry` GitHub environment of this repository (#107). Pushes and tags `sft/*` only. Mirrors get their own role when the mirror workflow lands |
| Osaka | With `replicate_to_osaka`: the key's replica, a replication rule for every repository and a creation template that gives the replicas that key, the same immutability and the same pull policy |

The `registry` GitHub environment must exist, accepting deployments from `main` only, before the push role is
created, for the same reason as the deploy roles' environments (infra/README.md, "Apply order"). The build workflow
reads the role and the registry host from the repository variables `ECR_PUSH_ROLE_ARN` and `ECR_REGISTRY`.
