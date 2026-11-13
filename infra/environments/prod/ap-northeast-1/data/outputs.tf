# Read by the cluster and cluster-bootstrap stacks and by the application's settings (infra/modules/data-stack).
# The keys and buckets (#102) are at the end, then the flow log's bucket, which the network's second apply takes.

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

output "kms_key_arns" {
  description = "ARN of each data class's key in this Region, by class (encryption 4.1). Osaka's data stack takes this as primary_key_arns."
  value       = module.data.kms.key_arns
}

output "kms_alias_names" {
  description = "Alias of each data class's key, alias/sft/<env>/<class>."
  value       = module.data.kms.alias_names
}

output "kms_osaka_key_arns" {
  description = "ARN each key's Osaka replica has once Osaka's data stack makes it."
  value       = module.data.kms.osaka_key_arns
}

output "files_bucket_names" {
  description = "The files buckets in this Region: files (up to 2 GB) and large-files."
  value       = module.data.storage.files_bucket_names
}

output "events_delivery_role_arn" {
  description = "sft-<env>-events-delivery, the role_arn for every EventBridge target into our queues and topics."
  value       = module.data.storage.events_delivery_role_arn
}

output "malware_protection_plan_arn" {
  description = "The large-files bucket's GuardDuty Malware Protection plan, or null where it is off."
  value       = module.data.storage.malware_protection_plan_arn
}

output "flow_log_bucket_arn" {
  description = "The VPC flow log's bucket in this Region, sft-<env>-<region-short>-flow-logs-<account-id>, as a bucket ARN: the network root's flow_log_destination_arn for its second apply (infra/README.md, \"Apply order\")."
  value       = module.data.storage.flow_log_bucket_arn
}
