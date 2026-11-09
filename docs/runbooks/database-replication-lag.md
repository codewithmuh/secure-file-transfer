# Runbook: database replication lag (`sft-<env>-apne3-database-rpo-lag`)

A CloudWatch alarm on Osaka's Aurora secondary ([ADR-0011](../adr/0011-database-aurora-global.md), NFR-10), defined in
[`infra/modules/alarms/database.tf`](../../infra/modules/alarms/database.tf). Severity: page. Staging and prod only;
dev has no replica.

## Symptoms

- `AuroraGlobalDBRPOLag` on `sft-<env>-apne3-aurora` has been above 60 seconds for 5 minutes.

## Impact

Nothing users see: Tokyo keeps serving. But a regional failover now would lose more metadata than the lag, and NFR-10
allows at most 5 minutes. Security-critical changes are safe either way, because they reach both Regions' audit
archives before the API confirms them (architecture 5.2), but ordinary changes in the lag would be lost.

## Confirm

All commands are for the live run, with the environment's named profile; the alarm is pending the AWS run.

```bash
# The lag and the global database's members, from Osaka
aws cloudwatch get-metric-statistics --region ap-northeast-3 --namespace AWS/RDS --metric-name AuroraGlobalDBRPOLag \
  --dimensions Name=DBClusterIdentifier,Value=sft-<env>-apne3-aurora --statistics Maximum --period 60 \
  --start-time "$(date -u -v-1H +%FT%TZ)" --end-time "$(date -u +%FT%TZ)"
aws rds describe-global-clusters --region ap-northeast-1 --global-cluster-identifier sft-<env>
# Write load in Tokyo: a burst of writes (a bulk job, a migration) makes the lag grow for a while
aws cloudwatch get-metric-statistics --region ap-northeast-1 --namespace AWS/RDS --metric-name WriteIOPS \
  --dimensions Name=DBClusterIdentifier,Value=sft-<env>-apne1-aurora --statistics Average --period 300 \
  --start-time "$(date -u -v-3H +%FT%TZ)" --end-time "$(date -u +%FT%TZ)"
```

Check the [AWS Health Dashboard](https://health.aws.amazon.com/health/status) for RDS in Tokyo and Osaka.

## Mitigate

1. **A write burst** (a backfill, the field-key job, a large purge): the lag drains once it ends. Pause the job if it
   runs for long; the purge and backfill jobs resume where they stopped.
2. **The secondary's instance is too small** (prod's is `db.r8g.large`, staging's is serverless up to 16 ACUs): its
   CPU and replica lag rise together. Size it up through the `data` stack in Osaka, a reviewed change.
3. **AWS-side replication trouble**: open a support case with the global cluster's ID. Don't detach or re-create the
   secondary in a hurry: until it catches up, Osaka has no recovery point at all.
4. **A failover is being decided while the lag is high**: record the lag in the decision; the regional failover
   runbook (`regional-failover.md`) re-applies security-critical changes from the archive, which covers what NFR-10
   protects.

## Escalate

If the lag is above 5 minutes for 30 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS): NFR-10's
RPO is broken until it recovers.

## Afterwards

Note the peak lag and its cause in the operating log; write a postmortem if NFR-10 was broken.
