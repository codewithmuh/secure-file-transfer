# 0007. Use ECR in the shared account for container images, signed and pinned by digest

- Status: accepted
- Date: 2026-11-03
- Issue: [#31](https://github.com/codewithmuh/secure-file-transfer/issues/31)

## Context

- **Where images live.** The registry can't live with prod: CI deploys to dev months before prod exists, and prod's
  teardown must neither take the images dev and staging use nor leave a registry billing. It replicates to Osaka once
  staging exists, for the pilot light and its drills, and costs about $4 a month
  ([capacity](../design/capacity-and-cost.md) 5.4, A40; [architecture](../architecture.md) 3.2).
- **Encryption.** Repositories use their own registry key in the shared stack, because a repository's encryption
  can't change after creation and an environment's keys go away with it. Node roles may only decrypt through ECR
  ([encryption](../security/encryption-and-keys.md) 3.1, 4.4).
- **What may run** ([threat model](../threat-model.md) T-68, T-70). Our images are built once, signed keylessly with
  cosign and deployed by digest. Third-party images (Argo CD, Karpenter, External Secrets, monitoring, CoreDNS, clamd)
  are mirrored, pinned by digest in Git and checked against their vendor signatures where one exists. An admission
  policy rejects anything else. No released image has a known critical or high vulnerability (NFR-13), and the same
  digests are promoted dev → staging → prod (NFR-18).
- **What the template does.** `release.yml` publishes both sample images to GHCR when a release is created, signs them
  with cosign through GitHub OIDC, and attaches SBOMs and build provenance. Architecture section 9 lists GHCR as the
  main alternative.

## Decision

Keep container images in **Amazon ECR in the shared account** ([ADR-0006](0006-aws-account-per-environment.md)),
in Tokyo, replicated to Osaka once staging exists, encrypted with the registry key. Tags are immutable; each build is
tagged with its Git SHA and deployed by digest. The build on `main` signs each digest keylessly with cosign through
GitHub OIDC and attaches its SBOM and provenance. Third-party images are copied by digest into mirror repositories
after their signatures and scans pass. An admission controller in every cluster enforces all of it. **GHCR publishing
is dropped**: ECR is the only registry.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **ECR in the shared account** (chosen) | Pulls stay inside AWS through the VPC endpoints, with no NAT traffic or internet dependency, in Osaka during a failover too (capacity 5.4). IAM and our own KMS key govern push, pull and encryption. Replication to Osaka is built in. The registry outlives each environment's teardown. | Nothing can be pushed until the AWS accounts exist. Cross-account pull policies for each environment account. Images aren't public for readers of the repository. ECR's own scanning isn't used, so re-scanning running digests is ours. |
| **GHCR, as the template publishes** | Already works: the release workflow, `GITHUB_TOKEN` authentication and keyless signing. Needs no AWS. Public images are easy. | Nodes pull from the internet through NAT, at $0.062/GB, and a failover would depend on GitHub's availability. Pulling private packages needs a credential in every cluster. No KMS key of ours, no replication to Osaka, and a second identity system decides what runs in prod. |
| **ECR in each environment account** | No cross-account access. | The same digest must be pushed or replicated into every account; each account's repositories die with its environment and its key (encryption 3.1); dev's images would exist before anything else in the account does. |
| **ECR for the clusters and GHCR as a public copy** | Readers can pull the images. | Two registries, two sets of tags, credentials and signatures to keep in step, for a need no requirement states. |

## Consequences

- **Repositories.** `sft/app` holds the one application image (architecture 2); `mirror/…` holds third-party images.
  The shared stack's deploy role creates them with the registry key and immutable tags. Lifecycle rules keep the last
  30 builds from `main` and every released version (A40); a CI check fails a deploy config that names a digest not in
  ECR.
- **Build and sign** ([ADR-0005](0005-terraform-github-actions-argo-cd.md)). On every merge to `main`, CI builds once,
  fails on a critical or high Trivy finding, pushes `sft/app:<git-sha>` through an OIDC role in shared that may push
  only to `sft/*`, and signs the digest. The SBOM (SPDX) and provenance are attached as artifacts of that digest; the
  release-please release links the digest and attaches the SBOM, as the template does today.
- **Signing identity.** Admission accepts an `sft/*` image only with a certificate whose identity is this repository's
  build workflow on `main`, issued by GitHub's OIDC issuer. Keyless signing records that identity and the digest in
  the public Rekor log. The admission controller must verify from the bundle stored with the signature, so a deploy or
  a failover doesn't depend on reaching Sigstore; the first build milestone confirms it.
- **Third-party images** (T-70). A mirror workflow copies each image that Git pins, by digest, into `mirror/`, verifies
  the vendor's signature where one is published, and runs Trivy. Admission accepts a mirrored digest with its
  allow-listed vendor identity, or, for a vendor that publishes no signature, the digest reviewed and listed in Git.
  ECR pull-through cache, which capacity A40 assumes, is not used: what it stores depends on when a node first asks,
  and an Osaka node's first pull during a failover would depend on the upstream registry.
- **Admission controller.** Kyverno, from the same mirror, requires a digest and a matching signature in every
  namespace, the platform's included. It is a new item in capacity's platform list (4.3).
- **Osaka.** A replication rule copies every repository to ap-northeast-3; a repository creation template applies the
  Osaka copy of the registry key. Signatures and SBOMs live in the same repositories and replicate with the images.
- **Pulls.** Each environment's node role may pull from `sft/*` and `mirror/*` and decrypt through ECR only; pulls go
  through the VPC endpoints and add nothing to NAT.
- **Re-scanning.** A scheduled workflow re-scans the digests that the deploy config names and opens an issue on any
  new critical or high finding (NFR-13).
- **Dropping GHCR.** In the first build milestone, `release.yml` stops logging in to and publishing to GHCR, in the
  same change that adds the ECR push and removes the Go sample ([ADR-0010](0010-no-go-in-v1.md)). Until then the
  template's workflow runs unchanged. The README line about GHCR changes with it.

When to revisit: if the project needs public images, for example a guide to run it yourself (add a public copy then);
if verifying signatures turns out to need Sigstore at deploy time; or if a customer's dedicated deployment needs its
own registry.
