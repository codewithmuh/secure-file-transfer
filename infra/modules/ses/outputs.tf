output "identity_arn" {
  description = "The domain identity mail.<service domain>: the user pool sends as it (ADR-0016)."
  value       = aws_sesv2_email_identity.mail.arn
}

output "from_address" {
  description = "no-reply@mail.<service domain>, the From of every service email (MAIL_FROM_ADDRESS)."
  value       = "no-reply@${local.mail_domain}"
}

output "configuration_set" {
  description = "sft-<env>: the notification worker's SES_CONFIGURATION_SET, and the user pool's."
  value       = aws_sesv2_configuration_set.this.configuration_set_name
}

output "events_topic_arn" {
  description = "The SNS topic SES publishes this Region's events to."
  value       = aws_sns_topic.events.arn
}
