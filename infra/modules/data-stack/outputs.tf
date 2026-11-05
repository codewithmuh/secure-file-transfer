output "aurora" {
  description = "The cluster: identifier, resource ID, endpoints, port, database, security group and master secret ARN (null for the secondary)."
  value = {
    cluster_identifier  = module.aurora.cluster_identifier
    cluster_resource_id = module.aurora.cluster_resource_id
    endpoint            = module.aurora.endpoint
    reader_endpoint     = module.aurora.reader_endpoint
    port                = module.aurora.port
    database_name       = module.aurora.database_name
    security_group_id   = module.aurora.security_group_id
    master_secret_arn   = module.aurora.master_secret_arn
  }
}

output "valkey" {
  description = "The counter store: cache ARN, endpoint, users by workload and security group."
  value = {
    cache_arn         = module.valkey.cache_arn
    endpoint          = module.valkey.endpoint
    user_arns         = module.valkey.user_arns
    security_group_id = module.valkey.security_group_id
  }
}

output "queues" {
  description = "The queues: ARNs and URLs by short name, and the dead-letter queues' ARNs."
  value = {
    queue_arns             = module.queues.queue_arns
    queue_urls             = module.queues.queue_urls
    dead_letter_queue_arns = module.queues.dead_letter_queue_arns
  }
}
