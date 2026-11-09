# Runbook: database capacity (`sft-<env>-<rs>-database-cpu`, `-database-memory`)

CloudWatch alarms on the Aurora writer ([ADR-0011](../adr/0011-database-aurora-global.md)), defined in
[`infra/modules/alarms/database.tf`](../../infra/modules/alarms/database.tf). Severity: ticket.

## Symptoms

- The writer's `CPUUtilization` has been above 80 % for 15 minutes, or
- its `FreeableMemory` has been below about a tenth of the instance's memory for 15 minutes.

## Impact

None yet; it is a warning. Left alone, queries slow down and API latency (NFR-2) and every job's run time follow.

## Confirm

Commands are for the live run; the alarms are pending the AWS run.

```bash
# Which statements cost most: Performance Insights, or pg_stat_statements as the operator role
aws pi get-resource-metrics --region <region> --service-type RDS --identifier <db resource id> \
  --metric-queries '[{"Metric":"db.load.avg","GroupBy":{"Group":"db.sql_tokenized","Limit":5}}]' \
  --start-time "$(date -u -v-1H +%FT%TZ)" --end-time "$(date -u +%FT%TZ)" --period-in-seconds 300
# Connections: a pool leak shows as a climbing count
aws cloudwatch get-metric-statistics --region <region> --namespace AWS/RDS --metric-name DatabaseConnections \
  --dimensions Name=DBClusterIdentifier,Value=sft-<env>-<rs>-aurora Name=Role,Value=WRITER --statistics Maximum \
  --period 300 --start-time "$(date -u -v-3H +%FT%TZ)" --end-time "$(date -u +%FT%TZ)"
```

Compare with the load: the API's request rate on the Grafana service dashboard, and which lifecycle jobs ran.

## Mitigate

1. **A job or a load test** (the k6 test, a purge, the field-key backfill): it ends on its own; note it.
2. **One expensive query** after a deploy: roll the deploy back (deploy config revert, NFR-18), then fix the query or
   its index forward.
3. **Steady growth**: size the writer up through the Region's `data` stack (a reviewed change; Aurora fails over to the
   resized instance in about a minute), and update capacity 5.2.

## Escalate

If CPU stays above 95 % or the API's latency SLO starts burning, the burn-rate page takes over; escalate to the owner
in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Record the cause and any size change in the capacity estimate.
