# The out-of-cluster watchdog (ADR-0009). Alertmanager sends the always-firing Watchdog alert (deploy/alerts) to the
# heartbeat topic every minute, through the egress proxy's platform listener. SNS counts each message in
# NumberOfMessagesPublished; when five minutes pass with none, this alarm pages. Missing data breaches, so a dead
# Prometheus, Alertmanager, proxy or cluster, or a cluster that no longer exists, all page the same way.
#
# In Osaka the alarm exists but doesn't notify during the pilot light, where no observability stack runs; the failover
# runbook applies this stack with TF_VAR_heartbeat_enabled=true (architecture 7).

resource "aws_cloudwatch_metric_alarm" "heartbeat_missing" {
  alarm_name        = "${var.name_prefix}-heartbeat-missing"
  alarm_description = "No heartbeat from the cluster's Alertmanager for 5 minutes: in-cluster alerting may be down (ADR-0009). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/watchdog.md"

  namespace   = "AWS/SNS"
  metric_name = "NumberOfMessagesPublished"
  dimensions  = { TopicName = aws_sns_topic.this["heartbeat"].name }
  statistic   = "Sum"
  period      = 60

  comparison_operator = "LessThanThreshold"
  threshold           = 1
  evaluation_periods  = 5
  datapoints_to_alarm = 5
  treat_missing_data  = "breaching"

  actions_enabled = var.heartbeat_enabled
  alarm_actions   = local.notify.page
  ok_actions      = local.notify.page

  tags = { component = "alarms" }
}
