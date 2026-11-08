# user-pool module

One Region's member user pool ([ADR-0016](../../../docs/adr/0016-member-sign-in-cognito.md); authn and authz 2).
Written by [#185](https://github.com/codewithmuh/secure-file-transfer/issues/185) and called by the `identity` root:
Tokyo's pool in every environment, Osaka's standby in staging and prod, from the same code and with no users. Nothing
here has been applied (infra/README.md).

| | |
|---|---|
| Pool | `sft-<env>-<region-short>-members`, Plus tier with threat protection enforced; deletion protection in prod. Admin-only sign-up, recovery by an admin only |
| Sign-in | Our user ID is the username, case-insensitive; the address is a verified `email` alias. A password of at least 15 characters (the temporary one lasts 3 days, `TEMPORARY_PASSWORD_DAYS`) or a passkey with user verification; MFA required, by TOTP. No SMS, no email codes |
| Schema | `custom:tenant_id` (immutable, 36 characters), `custom:enrolment_id`, and `custom:sso_groups` (mutable, up to 2,048 characters), where a tenant's identity provider maps its group claim for the API's group-to-role mapping (#231). Cognito writes several groups as one string, `[a,b]`, each URL-encoded. Cognito can't change a pool's schema, so a later attribute is a new block; `schema` changes are ignored, so a pool created before a new block needs `add-custom-attributes` (none has been applied yet) |
| Email | Cognito's own emails go through the Region's SES identity, as `no-reply@mail.<service domain>`, with the configuration set (modules/ses). Invitations are ours: the notification worker calls `AdminCreateUser` with `MessageAction=SUPPRESS` and sends the catalog's email (#193) |
| Domain | Managed login (version 2) on the prefix `sft-<env>-<region-short>-<hash>`, under `*.auth.<region>.amazoncognito.com`, which DNS Firewall already admits. The hash is of the account ID, so nobody else can claim our names first and the ID itself is never shown |
| App client | One confidential client for the API: the authorization code grant with PKCE, `openid email`, one callback (`https://api.<service domain>/v1/auth/callback`), token revocation on, 5-minute tokens. It reads `custom:sso_groups`, and may write `email` and `custom:sso_groups` only: Cognito writes an attribute an identity provider maps only if the client may write it ([attribute mapping](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html)). Members still write none: the client grants no `aws.cognito.signin.user.admin` scope and no direct sign-in flow |
| Web ACL | The edge's sign-in web ACL, once the edge exists (abuse 3) |

**The client secret.** Creating the client makes Cognito generate a first secret, which lands in Terraform's state.
The key rotation job's first run adds a second one, writes it to `sft/<env>/app/idp-client/<region>` and deletes the
first after 15 minutes (Osaka's after a day), so state only keeps a dead value (encryption and keys 6.4). The client's
secret is never an output.

The pre- and post-authentication triggers are one function from `modules/signin-triggers` (#238), which the pool
names in `lambda_config` (`trigger_function_arn`).
