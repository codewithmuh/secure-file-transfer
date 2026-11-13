# web-bundles module

The web app's versioned bundle store in the shared account ([ADR-0008](../../../docs/adr/0008-web-app-s3-cloudfront.md),
[ADR-0005](../../../docs/adr/0005-terraform-github-actions-argo-cd.md)), and the role that publishes to it. Written by
[#283](https://github.com/codewithmuh/secure-file-transfer/issues/283). Nothing here has been applied (infra/README.md).

| What | How |
|---|---|
| Bucket | `sft-shared-apne1-web-bundles-<account>`: versioned, SSE-S3 (public content, encryption 3.1), Block Public Access, owner enforced, TLS only. Replaced versions expire after 30 days; bundles stay while the shared account does, so every version an environment ran can be restored |
| Layout | `bundles/<git-sha>/<path>` for each file of a build of `main`, then `bundles/<git-sha>/manifest.json`, written last: each file's SHA-256, size, content type and cache header (`.github/scripts/web-release.sh`) |
| Writers | The publish role, and the deploy role at teardown. The bucket policy denies object writes and deletes to everyone else, `BreakGlass` included |
| Readers | Each environment's release role, `sft-<env>-web-release` (modules/web-release), by its exact ARN in the account `member_account_ids` names: `GetObject` under `bundles/`, no listing |
| Publish role | `sft-shared-web-publish` under `/sft-shared/`, trusting only the `registry` GitHub environment of this repository (main only, T-71), like the image push role: put and get under `bundles/`, list the bucket so a missing bundle answers 404, not 403 |

## Why a pointer and a digest

An environment serves the bundle `deploy/environments/<env>/web.yaml` names: a version and the digest of its manifest.
The deploy job checks the stored manifest against that digest and every file against the manifest before it writes
anything, so neither a changed object here nor a re-run publish can change what browsers load without a reviewed
commit. That is what makes a promotion and a rollback "move a pointer, as images do".

## Outputs

`bucket_name` and `publish_role_arn`, for the repository variables `WEB_BUNDLE_BUCKET` and `WEB_PUBLISH_ROLE_ARN`
that `.github/workflows/web.yml` and `web-deploy.yml` read.
