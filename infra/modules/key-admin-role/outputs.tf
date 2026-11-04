output "role_arn" {
  description = "ARN of the key-admin role, which every key policy in the account names."
  value       = aws_iam_role.key_admin.arn
}
