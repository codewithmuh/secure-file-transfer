output "role_arn" {
  description = "ARN of sft-<env>-break-glass-db, which BreakGlass assumes with the grant's session tag (docs/runbooks/break-glass.md)."
  value       = var.create_role ? aws_iam_role.this[0].arn : local.role_arn
}

output "alert_topic_arn" {
  description = "ARN of this Region's break-glass alert topic, for M7's subscriptions (the pager and every operator)."
  value       = aws_sns_topic.alerts.arn
}
