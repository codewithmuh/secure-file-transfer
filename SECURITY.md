# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub private vulnerability reporting](https://github.com/codewithmuh/secure-file-transfer/security/advisories/new)
or email **contact@codewithmuh.com** with:

- what is affected (service, version or commit),
- how to reproduce it,
- the impact you expect.

You will get an acknowledgement within **3 business days** and a plan within **10 business days**.
Fixes are released as a patch version and credited in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## How this repository protects itself

| Control | Where |
|---|---|
| Secret scanning on every commit and pull request | `.pre-commit-config.yaml`, `ci.yml` (gitleaks) |
| Dependency and base-image updates every week | `.github/dependabot.yml` |
| Vulnerability and misconfiguration scans (repo + images) | `ci.yml` (Trivy) |
| GitHub Actions pinned to commit SHAs, least-privilege tokens | `.github/workflows/*` |
| Containers run as non-root, read-only, all capabilities dropped | `Dockerfile`s, `compose.yaml` |
| Signed images (cosign, keyless) with SBOM and provenance | `build.yml` (ECR in the shared account, [ADR-0007](docs/adr/0007-container-registry-ecr.md)); `release.yml` (GHCR, until the first ECR build) |

Verify a published image:

```bash
cosign verify ghcr.io/codewithmuh/secure-file-transfer/api:<version> \
  --certificate-identity 'https://github.com/codewithmuh/secure-file-transfer/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

An image built on `main` for ECR is verified the same way, with the build workflow's identity:

```bash
cosign verify <shared-account>.dkr.ecr.ap-northeast-1.amazonaws.com/sft/app@sha256:<digest> \
  --certificate-identity 'https://github.com/codewithmuh/secure-file-transfer/.github/workflows/build.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Once the first ECR build has run, GHCR publishing and the first command go away (ADR-0007).
