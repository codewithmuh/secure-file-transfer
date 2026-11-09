output "topic_arns" {
  description = "The Region's alert topics by name: alerts-page, alerts-ticket and heartbeat. Alertmanager publishes to all three (deploy/alerts/alertmanager.yaml)."
  value       = { for t, topic in aws_sns_topic.this : t => topic.arn }
}

output "region_health_topic_arns" {
  description = "The us-east-1 topics of the Route 53 health check alarms, by severity; empty outside Tokyo's stack."
  value       = { for s, topic in aws_sns_topic.region_health : s => topic.arn }
}

output "alarm_names" {
  description = "Every alarm this stack makes, for the runbooks and the drills."
  value = concat(
    [aws_cloudwatch_metric_alarm.heartbeat_missing.alarm_name],
    aws_cloudwatch_metric_alarm.database_rpo_lag[*].alarm_name,
    aws_cloudwatch_metric_alarm.database_cpu[*].alarm_name,
    aws_cloudwatch_metric_alarm.database_memory[*].alarm_name,
    [for a in aws_cloudwatch_metric_alarm.dead_letter : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.queue_age : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.replication_failed : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.replication_latency : a.alarm_name],
    [aws_cloudwatch_metric_alarm.load_balancer_5xx.alarm_name, aws_cloudwatch_metric_alarm.api_targets.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.nat_port_allocation : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.nat_packet_drops : a.alarm_name],
    [aws_cloudwatch_metric_alarm.kms_quota.alarm_name, aws_cloudwatch_metric_alarm.ses_reputation.alarm_name],
    [aws_cloudwatch_metric_alarm.signin_trigger_errors.alarm_name, aws_cloudwatch_metric_alarm.signin_trigger_throttles.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.region_health : a.alarm_name],
  )
}
