# web-release module

The web app's release role in one environment account, `sft-<env>-web-release`
([ADR-0008](../../../docs/adr/0008-web-app-s3-cloudfront.md), [#283](https://github.com/codewithmuh/secure-file-transfer/issues/283)).
Tokyo's edge stack calls it once per account; nothing here has been applied (infra/README.md).

| | |
|---|---|
| Trust | GitHub's OIDC provider in this account, for one subject: the GitHub environment `web-<env>` of this repository, which accepts deployments from `main` only (docs/runbooks/organization-and-bootstrap.md, step 0). Not `<env>`, whose subject the Terraform deploy role trusts, so a web job can never become the deploy role (T-71) |
| May | `GetObject` under `bundles/` in the shared account's bundle store (modules/web-bundles), by name; `PutObject` in the environment's web buckets, `sft-<env>-<rs>-web-<account>`, in each Region with one |
| May not | Delete anything, list either bucket, or touch a distribution: a release adds files and replaces `config.json`, `index.html` and `release.json`, so a rollback finds every older version's files in place |

The web buckets' policy (modules/edge, `web_writer_arns`) denies object writes to everyone but this role and the
deploy role, which empties a bucket at teardown. The edge stacks' deploy permissions create and change this role only
(`terraform-oidc-roles/permissions-edge.tf`), and its name comes from the conventions module's `edge` role list.

`.github/workflows/web-deploy.yml` assumes it as `arn:aws:iam::<account>:role/sft-<env>-web-release`, the account from
the `web-<env>` environment's variable `AWS_ACCOUNT_ID`.
