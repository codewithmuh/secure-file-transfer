output "cluster_identifier" {
  description = "The cluster's name: sft-<env>-<region-short>-aurora."
  value       = local.cluster.cluster_identifier
}

output "cluster_arn" {
  description = "ARN of the cluster."
  value       = local.cluster.arn
}

output "cluster_resource_id" {
  description = "The cluster's resource ID, which rds-db:connect ARNs name: arn:aws:rds-db:<region>:<account>:dbuser:<id>/<login role>."
  value       = local.cluster.cluster_resource_id
}

output "endpoint" {
  description = "The writer endpoint. In the Osaka secondary it answers only after a promotion."
  value       = local.cluster.endpoint
}

output "reader_endpoint" {
  description = "The reader endpoint: audit search and other read-only queries."
  value       = local.cluster.reader_endpoint
}

output "port" {
  description = "PostgreSQL's port."
  value       = local.cluster.port
}

output "database_name" {
  description = "The application database."
  value       = var.database_name
}

output "global_cluster_identifier" {
  description = "The global database this cluster belongs to, or null for a standalone cluster."
  value       = local.standalone ? null : var.global_cluster_identifier
}

output "security_group_id" {
  description = "The cluster's security group, which admits only client_security_group_ids on 5432."
  value       = aws_security_group.this.id
}

output "log_group_name" {
  description = "The cluster's PostgreSQL log in CloudWatch Logs."
  value       = aws_cloudwatch_log_group.postgresql.name
}

output "master_secret_arn" {
  description = "ARN of sft/<env>/db/master, or null where this Region holds no master secret (the secondary)."
  value       = one(aws_secretsmanager_secret.master[*].arn)
}
