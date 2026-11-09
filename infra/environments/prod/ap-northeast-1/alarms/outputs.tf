output "topic_arns" {
  description = "The Region's alert topics: alerts-page, alerts-ticket and heartbeat, which Alertmanager publishes to."
  value       = module.alarms.topic_arns
}

output "alarm_names" {
  description = "Every alarm this stack makes."
  value       = module.alarms.alarm_names
}

output "region_health_topic_arns" {
  description = "The us-east-1 topics of the Route 53 health check alarms, by severity."
  value       = module.alarms.region_health_topic_arns
}
