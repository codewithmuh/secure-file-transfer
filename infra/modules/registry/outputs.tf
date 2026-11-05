output "registry_host" {
  description = "The registry's host in Tokyo, for the ECR_REGISTRY repository variable (#107)."
  value       = "${var.account_id}.dkr.ecr.${local.region}.amazonaws.com"
}

output "repository_urls" {
  description = "Repository URLs by name."
  value       = { for name, repository in aws_ecr_repository.this : name => repository.repository_url }
}

output "registry_key_arn" {
  description = "ARN of the registry key in Tokyo."
  value       = aws_kms_key.registry.arn
}

output "registry_key_osaka_arn" {
  description = "ARN of the registry key's Osaka replica, or null before replication is on."
  value       = one(aws_kms_replica_key.registry_osaka[*].arn)
}

output "push_role_arn" {
  description = "ARN of the push role, for the ECR_PUSH_ROLE_ARN repository variable (#107)."
  value       = aws_iam_role.push.arn
}
