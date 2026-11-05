output "queue_arns" {
  description = "Queue ARNs by short name, for the workloads' policies and the platform key's aws:sqs:arn conditions."
  value       = { for k, q in aws_sqs_queue.this : k => q.arn }
}

output "queue_urls" {
  description = "Queue URLs by short name."
  value       = { for k, q in aws_sqs_queue.this : k => q.id }
}

output "queue_names" {
  description = "Queue names by short name: <name_prefix>-<short name>. The application's SQS_QUEUE_PREFIX is <name_prefix>-."
  value       = { for k, q in aws_sqs_queue.this : k => q.name }
}

output "dead_letter_queue_arns" {
  description = "Dead-letter queue ARNs by the short name of the queue they serve, for the dead-letter alarms."
  value       = { for k, q in aws_sqs_queue.dead_letter : k => q.arn }
}

output "dead_letter_queue_urls" {
  description = "Dead-letter queue URLs by the short name of the queue they serve."
  value       = { for k, q in aws_sqs_queue.dead_letter : k => q.id }
}

output "queue_names_by_sender_role" {
  description = "Short names of the queues each sender role is the only sender to, by role ARN: the role's own policy names exactly these (#102, events-delivery-role)."
  value = {
    for arn in distinct(values(local.role_senders)) :
    arn => sort([for name, sender in local.role_senders : name if sender == arn])
  }
}
