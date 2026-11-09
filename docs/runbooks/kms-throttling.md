# Runbook: KMS throttling (`sft-<env>-<rs>-kms-quota`)

A CloudWatch alarm on the account's symmetric KMS request rate against its quota
([encryption](../security/encryption-and-keys.md) 4), defined in
[`infra/modules/alarms/kms.tf`](../../infra/modules/alarms/kms.tf). Severity: ticket.

## Symptoms

`AWS/Usage` `CallCount` for KMS `CryptographicOperationsSymmetric` has been above 80 % of the Region's quota for 5
minutes.

## Impact

None yet. At the quota, KMS throttles: S3 uploads and downloads with SSE-KMS, SQS messages, Secrets Manager reads and
the field keys' unwraps slow down and retry, and `FieldKeysUnavailable` may page.

## Confirm

Commands are for the live run; the alarm is pending the AWS run.

```bash
# Which caller: CloudTrail's KMS events by user identity over the last hour
aws cloudtrail lookup-events --region <region> --lookup-attributes AttributeKey=EventSource,AttributeValue=kms.amazonaws.com \
  --start-time "$(date -u -v-1H +%FT%TZ)" --max-results 50 --query 'Events[].Username'
aws service-quotas get-service-quota --region <region> --service-code kms --quota-code L-6E3AF000
```

S3 Bucket Keys should keep S3's calls low: a bucket without them (a drifted setting) multiplies the calls.

## Mitigate

1. **A load test or a backfill**: expected; note it.
2. **A bucket without Bucket Keys, or a queue's data key reuse period changed**: re-apply the `data` stack.
3. **Real growth**: request a quota increase in Service Quotas, and record it in capacity 5.

## Escalate

If requests are throttled (`ThrottlingException` in the workers' logs) and users are affected, escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Note the cause and any quota change.
