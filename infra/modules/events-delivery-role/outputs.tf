output "role_arn" {
  description = "ARN of sft-<env>-events-delivery, for the role_arn of every rule target."
  value       = aws_iam_role.this.arn
}
