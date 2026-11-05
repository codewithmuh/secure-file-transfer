output "cache_name" {
  description = "The serverless cache's name: sft-<env>-<region-short>-valkey."
  value       = aws_elasticache_serverless_cache.this.name
}

output "cache_arn" {
  description = "ARN of the serverless cache, for elasticache:Connect in the workloads' policies."
  value       = aws_elasticache_serverless_cache.this.arn
}

output "endpoint" {
  description = "The primary endpoint: address and port (6379). TLS only."
  value = {
    address = aws_elasticache_serverless_cache.this.endpoint[0].address
    port    = aws_elasticache_serverless_cache.this.endpoint[0].port
  }
}

output "user_arns" {
  description = "ARNs of the IAM-authenticated users by workload, for elasticache:Connect in each workload's policy."
  value       = { for w, u in aws_elasticache_user.workload : w => u.arn }
}

output "user_names" {
  description = "User names by workload: the name each workload signs its IAM authentication token for."
  value       = { for w, u in aws_elasticache_user.workload : w => u.user_name }
}

output "security_group_id" {
  description = "The cache's security group, which admits only client_security_group_ids on 6379."
  value       = aws_security_group.this.id
}
