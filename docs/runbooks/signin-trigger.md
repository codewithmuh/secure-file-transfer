# Runbook: sign-in trigger (`sft-<env>-<rs>-signin-trigger-errors`, `-throttles`)

CloudWatch alarms on the Cognito sign-in triggers' function, `sft-<env>-<rs>-signin-trigger`
([authn-authz](../security/authn-authz.md) 2.4, threat model T-89), defined in
[`infra/modules/alarms/signin.tf`](../../infra/modules/alarms/signin.tf). Severity: page.

## Symptoms

- The function failed more than 5 times in 5 minutes, or
- Lambda throttled it at least once.

## Impact

Cognito denies a sign-in whose trigger fails, so members can't sign in while it lasts. Existing sessions, recipients,
uploaders and API keys keep working (architecture 6).

## Confirm

Commands are for the live run; the alarms are pending the AWS run.

```bash
aws logs tail /aws/lambda/sft-<env>-<rs>-signin-trigger --region <region> --since 30m
aws lambda get-function-concurrency --region <region> --function-name sft-<env>-<rs>-signin-trigger
```

The function's log has one JSON line per invocation, never a username or password. Typical failures: the counter store
unreachable (`RateLimitStoreUnavailable` pages too), the `signin-events` queue refusing sends, or a bad image after a
deploy.

## Mitigate

1. **After a deploy**: the function runs the API image; roll the image back with the deploy config and re-apply the
   `identity` stack with the previous digest.
2. **Counter store or queue unavailable**: follow that alert's runbook; the trigger denies sign-ins by design while
   either is down.
3. **Throttles**: account concurrency used up by something else in the Region, or a sign-in flood
   (`CredentialStuffing`); check the WAF's sign-in rules before raising concurrency.

## Escalate

If members can't sign in for 15 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Postmortem with the number of sign-ins denied.
