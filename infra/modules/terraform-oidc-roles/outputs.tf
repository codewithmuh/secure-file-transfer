output "oidc_provider_arn" {
  description = "ARN of the account's GitHub OIDC provider."
  value       = local.oidc_provider_arn
}

output "plan_role_arn" {
  description = "ARN of the Terraform plan role."
  value       = aws_iam_role.plan.arn
}

output "deploy_role_arn" {
  description = "ARN of the Terraform deploy role, or null when the account has none."
  value       = one(aws_iam_role.deploy[*].arn)
}
