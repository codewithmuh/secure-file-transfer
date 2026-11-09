# signin-triggers module

The Cognito sign-in triggers ([#238](https://github.com/codewithmuh/secure-file-transfer/issues/238);
[ADR-0016](../../../docs/adr/0016-member-sign-in-cognito.md), consequences;
[authn and authz](../../../docs/security/authn-authz.md) 2.4;
[abuse and rate limits](../../../docs/security/abuse-and-rate-limits.md) 2.3). One Lambda function per Region serves
both the pre- and the post-authentication trigger of that Region's user pool. Nothing here has been applied
(infra/README.md); running against Cognito is pending the AWS run.

| Piece | What it does |
|---|---|
| Function | `sft-<env>-<region-short>-signin-trigger`: the API image by digest (`image_uri`), entry point `python -m sft.workers.signin_trigger`, which speaks the Lambda Runtime API itself. arm64, 256 MB, 5 s (Cognito's limit for a trigger). Its environment holds the counter store's address and IAM user, the cache name and the queue prefix; no secret |
| Role | `sft-<env>-signin-trigger`, made by Tokyo's stack (`create_role`) for both Regions: `sqs:SendMessage` to the `signin-events` queues, the platform key through SQS for those queues only, `elasticache:Connect` as its own Valkey user, its own log groups, and its network interfaces. The queues' policies, the platform key's policy and the Valkey users already name it |
| Network | The private subnets. Its security group allows out only HTTPS to the interface endpoints' group and 6379 to the counter store, whose group this module opens to it. The network gives the private subnets no way out except through the system nodes' group |
| Logs | `/aws/lambda/<function>`, JSON, 90 days, encrypted with the logs key |
| Permission | `cognito-idp.amazonaws.com` may invoke it for this Region's user pool only |

The image comes from the shared registry, which lets Lambda pull `sft/app` for these functions
(modules/registry, `SignInTriggerFunctionsPull`). A function runs an image from its own Region's registry: Tokyo's, or
Osaka's replica.

The user pool names the function in `lambda_config` (modules/user-pool, `trigger_function_arn`). The identity roots
call both modules and take the image from `TF_VAR_signin_trigger_image`.

`tests/triggers.tftest.hcl` plans the module against a mocked provider (`infra/scripts/check.sh test`).
