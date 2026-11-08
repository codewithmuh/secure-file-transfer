# app-secrets module

One Region's application secrets, `sft/<env>/app/*` (encryption and keys 6.1, 6.4), created **without a value**.
Written by [#185](https://github.com/codewithmuh/secure-file-transfer/issues/185) and called by the `identity` root.
Nothing here has been applied (infra/README.md).

| Secret | Where | Read by |
|---|---|---|
| `csrf-hmac`, `email-hmac`, `code-hmac`, `link-hmac` | Tokyo, replicated to Osaka in staging and prod under Osaka's secrets key | The API and the notification worker, each as its own role, at start and every 5 minutes (6.4, #184) |
| `idp-client/<region>` | Each Region its own: Osaka's lives only in Osaka, so it stays writable while Tokyo is down | That Region's API, through External Secrets (`api-secrets`) |

Terraform never writes a value, so nothing secret reaches a plan or the state, and the deploy role has no
`PutSecretValue` or `GetSecretValue` on them. The key rotation job (`sft.workers.key_rotation`, deploy/charts/sft) is
their only writer: its first run writes every first version, so until it has run once the API and the notification
worker find no keyring and don't start (deploy/README.md). Each secret is under the Region's
secrets key; a deleted one can be restored for 30 days in prod, 7 elsewhere.
