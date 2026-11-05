# 0007. Use ECR in the shared account for container images, signed and pinned by digest

- Status: accepted
- Date: 2026-11-03
- Issue: [#31](https://github.com/codewithmuh/secure-file-transfer/issues/31)

## Context

- **Where images live.** The registry can't live with prod: CI deploys to dev months before prod exists, and prod's
  teardown must neither take the images dev and staging use nor leave a registry billing. It replicates to Osaka once
  staging exists, for the pilot light and its drills, and costs about $6 a month
  ([capacity](../design/capacity-and-cost.md) 5.4, A40; [architecture](../architecture.md) 3.2).
- **Encryption.** Repositories use their own registry key in the shared stack, because a repository's encryption
  can't change after creation and an environment's keys go away with it. Node roles may only decrypt through ECR
  ([encryption](../security/encryption-and-keys.md) 3.1, 4.4).
- **What may run** ([threat model](../threat-model.md) T-68, T-70). Our images are built once, signed keylessly with
  cosign and deployed by digest. Third-party images (Argo CD, Karpenter, Kyverno, External Secrets, KEDA, monitoring,
  the egress proxy, clamd) are mirrored, pinned by digest in Git and checked against their vendor signatures where one
  exists. The EKS add-ons come from AWS's own registries ([ADR-0004](0004-compute-eks-karpenter-argo-cd.md)). An
  admission policy rejects anything else. No released image has a known critical or high vulnerability (NFR-13), and
  the same digests are promoted dev → staging → prod (NFR-18).
- **What the template does.** `release.yml` publishes both sample images to GHCR when a release is created, signs them
  with cosign through GitHub OIDC, and attaches SBOMs and build provenance. Architecture section 9 lists GHCR as the
  main alternative.

## Decision

Keep container images in **Amazon ECR in the shared account** ([ADR-0006](0006-aws-account-per-environment.md)),
in Tokyo, replicated to Osaka once staging exists, encrypted with the registry key. Tags are immutable; each build is
tagged with its Git SHA and deployed by digest. The build on `main` signs each digest keylessly with cosign through
GitHub OIDC and attaches its SBOM and provenance. Third-party images are copied by digest into mirror repositories
after their signatures and scans pass. **Kyverno** enforces all of it in every cluster. **GHCR publishing is
dropped**: ECR is the only registry for our images.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **ECR in the shared account** (chosen) | Pulls stay inside AWS through the VPC endpoints, with no NAT traffic or internet dependency, in Osaka during a failover too (capacity 5.4). IAM and our own KMS key govern push, pull and encryption. Replication to Osaka is built in. The registry outlives each environment's teardown. | Nothing can be pushed until the AWS accounts exist. Cross-account pull policies for each environment account. Images aren't public for readers of the repository. ECR's own scanning isn't used, so re-scanning running digests is ours. |
| **GHCR, as the template publishes** | Already works: the release workflow, `GITHUB_TOKEN` authentication and keyless signing. Needs no AWS. Public images are easy. | Nodes pull from the internet through NAT, at $0.062/GB, and a failover would depend on GitHub's availability. Pulling private packages needs a credential in every cluster. No KMS key of ours, no replication to Osaka, and a second identity system decides what runs in prod. |
| **ECR in each environment account** | No cross-account access. | The same digest must be pushed or replicated into every account; each account's repositories die with its environment and its key (encryption 3.1); dev's images would exist before anything else in the account does. |
| **ECR for the clusters and GHCR as a public copy** | Readers can pull the images. | Two registries, two sets of tags, credentials and signatures to keep in step, for a need no requirement states. |

## Consequences

- **Repositories.** `sft/app` holds the one application image (architecture 2); `mirror/…` holds third-party images.
  The shared stack's deploy role creates them with the registry key and immutable tags.
- **Lifecycle.** A digest is tagged `deployed-<git-sha>`, a tag of its own because tags are immutable, once its pin
  lands on `main`: after each change to the deploy config, usually a promotion's merge, `mark-deployed.yml` (#107)
  tags every digest `main` pins, and `promote.yml` repeats it for the digest it copies, which has already landed in
  the previous environment. A build whose dev proposal is replaced before it merges is never tagged. The
  highest-priority lifecycle rule selects `deployed-*` with a count no repository reaches, so a deployed image never
  expires, whichever environment still pins it; only tagged builds never tagged deployed expire, beyond the newest 30
  (A40). No rule selects untagged images (next point), so a build that failed its scan, which is never tagged, stays
  until someone deletes it.
  Mirror repositories keep every digest that Git pins. A CI check fails a deploy config that names a digest not in
  ECR, and a daily check alerts on a pinned digest without its `deployed-` tag.
- **Signatures and attestations under the lifecycle.** cosign v3 (v3.0.6, from `cosign-installer` v4.1.2) stores each
  signature as a Sigstore bundle in an OCI 1.1 referrer: an untagged artifact whose subject is the image index. ECR's
  lifecycle removes a referrer within 24 hours after its subject expires (the ECR user guide, "Lifecycle policy
  evaluation rules"); the SBOM and provenance are manifests inside the index, which ECR won't expire before the index.
  The guide doesn't say that a rule selecting untagged images skips referrers whose subject is kept, so the lifecycle
  policy ([#105](https://github.com/codewithmuh/secure-file-transfer/issues/105)) has no such rule: its count rule
  selects only tagged images, and a kept image's signature, untagged, is never selected. Tag-based signatures could be
  taken: cosign's legacy `sha256-<digest>.sig` tags, or the `sha256-<digest>` tag that the OCI referrers fallback
  writes for a registry without the referrers API, are tagged images. ECR serves the referrers API, so none should
  appear; the policy still keeps every `sha256-` tag, in a rule above the count rule. The first build milestone checks
  with the lifecycle preview that no signature or attestation of a kept image is selected, and how many images a
  build adds to the count; if AWS documents that untagged rules skip referrers, a rule for failed builds can follow.
- **Build and sign** ([ADR-0005](0005-terraform-github-actions-argo-cd.md)). On every merge to `main` that changes
  code, CI builds once, fails on a critical or high Trivy finding, pushes `sft/app:<git-sha>` through an OIDC role in
  shared that may push only to `sft/*`, and signs the digest. The SBOM (SPDX) and provenance are attached as artifacts
  of that digest; the release-please release links the digest and attaches the SBOM, as the template does today.
  `build.yml` (#107) builds for `linux/arm64` only, natively on GitHub's `ubuntu-24.04-arm` runner, because every
  node pool is Graviton ([capacity](../design/capacity-and-cost.md) 4.1); `ci.yml` builds and smoke-tests the same
  Dockerfile on x86 before merge, and that image is never pushed. `build.yml` pushes the image by digest with no tag,
  scans that arm64 image, signs it, verifies the signature as admission will, and only then tags it `<git-sha>`, so
  the image scanned is the image that runs; a failed scan leaves an untagged, unsigned image that admission refuses
  and the lifecycle expires. A re-run finds the commit's tag and reuses its digest, but only once `cosign verify`
  accepts its signature with the identity below. Only that job may request an OIDC token, so nothing else can sign as
  `build.yml`; the job that opens dev's pull request has the bot's token and no AWS access. The push role trusts only
  the `registry` GitHub environment, which accepts deployments from `main` only (T-71).
- **Signing identity.** Admission accepts an `sft/*` image only with a certificate whose identity is this repository's
  build workflow on `main`, issued by GitHub's OIDC issuer. Keyless signing records that identity and the digest in
  the public Rekor log. Kyverno verifies offline, from the bundle stored with the signature and a Sigstore trust root
  (Fulcio's root certificates and the Rekor and certificate-transparency log keys) pinned in Git, so admission never
  calls Sigstore through the proxy, and a deploy or a failover doesn't depend on reaching it. A scheduled workflow
  compares the pinned root with Sigstore's published one and opens a pull request when it rotates. The first build
  milestone confirms the offline check.
- **Not yet checked before merge.** No role that a pull request may assume can read the registry: the push role
  trusts only the `registry` environment, and the plan roles have no ECR permissions. So neither CI nor
  `promotion-gate` can yet check that a digest in a pull request exists in ECR and is signed, as the lifecycle's CI
  check above and ADR-0005's fast reverts assume; a hand-edited dev digest passes them. Admission still refuses an
  unsigned digest, and `mark-deployed.yml` fails on the merge of a digest that isn't a build from `main`. The check
  needs a read-only registry role that trusts `pull_request` (`ecr:DescribeImages` and pulls on `sft/*`).
- **Third-party images** (T-70). A mirror workflow copies each image that Git pins, by digest, into `mirror/`, verifies
  the vendor's signature where one is published, and runs Trivy. Admission accepts a mirrored digest with its
  allow-listed vendor identity, or, for a vendor that publishes no signature, the digest reviewed and listed in Git.
  ECR pull-through cache, which capacity A40 assumes, is not used: what it stores depends on when a node first asks,
  and an Osaka node's first pull during a failover would depend on the upstream registry.
- **Admission controller.** Kyverno, from the same mirror, runs on the `system` node group (ADR-0004) and requires a
  digest and a matching signature from our mirrored or signed images. Its image policy also allows the named EKS
  add-ons (the VPC CNI, kube-proxy, CoreDNS, the Pod Identity agent, the EBS CSI driver and the pause image) by
  registry and repository from the AWS-owned EKS and Bottlerocket registry accounts for ap-northeast-1 and
  ap-northeast-3, and nothing else from them. Its blocking webhooks exclude `kube-system`, `karpenter`, `kyverno` and
  `argocd`, so a cold start can't deadlock (ADR-0004); there the same policies run in CI with the Kyverno CLI against
  the rendered manifests, whose images are pinned by digest in Git, and in Kyverno's background reports, which alert on
  a violation. It is in capacity's platform list (4.3).
- **Osaka.** A replication rule copies every repository to ap-northeast-3; a repository creation template applies the
  Osaka copy of the registry key. Signatures and SBOMs live in the same repositories and replicate with the images.
- **Pulls.** Each environment's node role may pull from `sft/*` and `mirror/*` and decrypt through ECR only, and pull
  the EKS add-ons from AWS's registries. Pulls go through the VPC endpoints, whose policies allow exactly those
  registries ([ADR-0021](0021-network-design-and-egress.md)), and add nothing to NAT.
- **Re-scanning.** A scheduled workflow re-scans the digests that the deploy config names and opens an issue on any
  new critical or high finding (NFR-13).
- **Dropping GHCR.** `build.yml` ([#107](https://github.com/codewithmuh/secure-file-transfer/issues/107)) adds the
  ECR push, and `SECURITY.md` shows how to verify its images. It can't run until the shared account exists, so
  `release.yml` keeps publishing to GHCR until the first ECR build on `main` has passed; the change after it stops
  `release.yml` logging in to and publishing to GHCR, drops `SECURITY.md`'s GHCR `cosign verify` example and changes
  the README line about GHCR. Until then a release still has a signed image and an SBOM somewhere.

When to revisit: if the project needs public images, for example a guide to run it yourself (add a public copy then);
if verifying signatures offline turns out not to work in Kyverno; or if a customer's dedicated deployment needs its own
registry.
