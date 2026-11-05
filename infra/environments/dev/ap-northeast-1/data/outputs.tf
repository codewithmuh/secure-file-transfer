# Read by the cluster and cluster-bootstrap stacks and by the application's settings (infra/modules/data-stack).
# Key and bucket outputs come with #102.

output "aurora_cluster_identifier" {
  description = "The Aurora cluster in this Region."
  value       = module.data.aurora.cluster_identifier
}

output "aurora_cluster_resource_id" {
  description = "The cluster's resource ID, for rds-db:connect ARNs."
  value       = module.data.aurora.cluster_resource_id
}

output "aurora_endpoint" {
  description = "The writer endpoint, port and database. TLS with sslmode=verify-full; IAM database authentication."
  value = {
    host     = module.data.aurora.endpoint
    port     = module.data.aurora.port
    database = module.data.aurora.database_name
  }
}

output "aurora_reader_endpoint" {
  description = "The reader endpoint."
  value       = module.data.aurora.reader_endpoint
}

output "aurora_security_group_id" {
  description = "The cluster's security group."
  value       = module.data.aurora.security_group_id
}

output "aurora_master_secret_arn" {
  description = "ARN of sft/<env>/db/master, for the database bootstrap job's policy."
  value       = module.data.aurora.master_secret_arn
}

output "valkey_cache_arn" {
  description = "The counter store, for elasticache:Connect in the workloads' policies."
  value       = module.data.valkey.cache_arn
}

output "valkey_endpoint" {
  description = "The counter store's endpoint: address and port. TLS and IAM authentication."
  value       = module.data.valkey.endpoint
}

output "valkey_user_arns" {
  description = "The counter store's users by workload, for elasticache:Connect in each workload's policy."
  value       = module.data.valkey.user_arns
}

output "valkey_security_group_id" {
  description = "The counter store's security group."
  value       = module.data.valkey.security_group_id
}

output "queue_arns" {
  description = "Queue ARNs by short name."
  value       = module.data.queues.queue_arns
}

output "queue_urls" {
  description = "Queue URLs by short name."
  value       = module.data.queues.queue_urls
}

output "dead_letter_queue_arns" {
  description = "Dead-letter queue ARNs by the short name of the queue they serve."
  value       = module.data.queues.dead_letter_queue_arns
}
