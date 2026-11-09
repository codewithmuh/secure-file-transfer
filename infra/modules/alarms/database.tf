# Aurora (ADR-0011). On Osaka's secondary, the global database's recovery point: AuroraGlobalDBRPOLag over a minute for
# five minutes pages, well inside NFR-10's 5 minutes of metadata. On the writer (Tokyo's primary, dev's standalone
# cluster), CPU and memory raise tickets: they mean the instance needs a size up before NFR-2 suffers, not an outage.
# The cluster-level metrics with Role = WRITER follow the writer through a failover inside the Region.

resource "aws_cloudwatch_metric_alarm" "database_rpo_lag" {
  count = var.database.role == "secondary" ? 1 : 0

  alarm_name        = "${var.name_prefix}-database-rpo-lag"
  alarm_description = "Osaka's database replica is more than a minute behind Tokyo for 5 minutes: a failover now would lose that much metadata (NFR-10, ADR-0011). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/database-replication-lag.md"

  namespace   = "AWS/RDS"
  metric_name = "AuroraGlobalDBRPOLag"
  dimensions  = { DBClusterIdentifier = var.database.cluster_identifier }
  statistic   = "Maximum"
  period      = 60

  comparison_operator = "GreaterThanThreshold"
  threshold           = 60000 # milliseconds
  evaluation_periods  = 5
  datapoints_to_alarm = 5
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.page
  ok_actions    = local.notify.page

  tags = { component = "alarms" }
}

resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  count = var.database.role == "secondary" ? 0 : 1

  alarm_name        = "${var.name_prefix}-database-cpu"
  alarm_description = "The database writer's CPU has been above 80 % for 15 minutes; API latency (NFR-2) is at risk. Severity: ticket. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/database-capacity.md"

  namespace   = "AWS/RDS"
  metric_name = "CPUUtilization"
  dimensions  = { DBClusterIdentifier = var.database.cluster_identifier, Role = "WRITER" }
  statistic   = "Average"
  period      = 300

  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.ticket
  ok_actions    = local.notify.ticket

  tags = { component = "alarms" }
}

resource "aws_cloudwatch_metric_alarm" "database_memory" {
  count = var.database.role == "secondary" ? 0 : 1

  alarm_name        = "${var.name_prefix}-database-memory"
  alarm_description = "The database writer's freeable memory has been low for 15 minutes; it will start swapping or evicting cache (NFR-2). Severity: ticket. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/database-capacity.md"

  namespace   = "AWS/RDS"
  metric_name = "FreeableMemory"
  dimensions  = { DBClusterIdentifier = var.database.cluster_identifier, Role = "WRITER" }
  statistic   = "Minimum"
  period      = 300

  comparison_operator = "LessThanThreshold"
  threshold           = var.database.freeable_memory_alarm_bytes
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.ticket
  ok_actions    = local.notify.ticket

  tags = { component = "alarms" }
}
