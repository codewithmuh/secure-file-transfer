# S3 replication with Replication Time Control, Tokyo to Osaka (ADR-0012, NFR-10; modules/files-buckets): RTC's
# metrics are on for the rule `to-osaka`, and published in Tokyo, the source's Region. A failed replication or a
# replica later than RTC's 15 minutes pages: a failover now would lose those files.
#
# The audit archive replicates without RTC, so it has no replication metrics: its security-critical records are
# written to both Regions directly (architecture 5.2), and the reconciliation job compares the two (#181).

resource "aws_cloudwatch_metric_alarm" "replication_failed" {
  for_each = var.replicated_buckets

  alarm_name        = "${var.name_prefix}-${each.key}-replication-failed"
  alarm_description = "Objects in ${each.value.source} failed to replicate to Osaka (NFR-10, ADR-0012). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/file-replication.md"

  namespace   = "AWS/S3"
  metric_name = "OperationsFailedReplication"
  dimensions = {
    SourceBucket      = each.value.source
    DestinationBucket = each.value.destination
    RuleId            = "to-osaka"
  }
  statistic = "Sum"
  period    = 300

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.page
  ok_actions    = local.notify.page

  tags = { component = "alarms" }
}

resource "aws_cloudwatch_metric_alarm" "replication_latency" {
  for_each = var.replicated_buckets

  alarm_name        = "${var.name_prefix}-${each.key}-replication-latency"
  alarm_description = "Replicas of ${each.value.source} in Osaka are more than 15 minutes behind, past RTC's commitment and NFR-10's bound. Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/file-replication.md"

  namespace   = "AWS/S3"
  metric_name = "ReplicationLatency"
  dimensions = {
    SourceBucket      = each.value.source
    DestinationBucket = each.value.destination
    RuleId            = "to-osaka"
  }
  statistic = "Maximum"
  period    = 300

  comparison_operator = "GreaterThanThreshold"
  threshold           = 900
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.page
  ok_actions    = local.notify.page

  tags = { component = "alarms" }
}
