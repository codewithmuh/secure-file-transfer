output "topic_arns" {
  description = "The Region's alert topics: alerts-page, alerts-ticket and heartbeat, which Alertmanager publishes to."
  value       = module.alarms.topic_arns
}

output "alarm_names" {
  description = "Every alarm this stack makes."
  value       = module.alarms.alarm_names
}
