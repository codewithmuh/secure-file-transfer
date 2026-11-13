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

output "kms" {
  description = "The keys (#102): ARN and alias of each class's key in this Region (in Osaka the replicas), and in Tokyo for staging and prod the ARN each key's Osaka replica has."
  value = {
    key_arns       = module.kms.key_arns
    alias_names    = module.kms.alias_names
    osaka_key_arns = module.kms.osaka_key_arns
  }
}

output "storage" {
  description = "The buckets and roles (#102): the files buckets, the audit archive (null in prod, whose archive is the retained stack's), EventBridge's delivery role (Tokyo only), the Malware Protection plan (null where it is off) and the VPC flow log's bucket ARN (flow-logs.tf)."
  value = {
    files_bucket_names          = module.files_buckets.bucket_names
    audit_archive_bucket_name   = one(module.audit_archive[*].bucket_name)
    events_delivery_role_arn    = one(module.events_delivery[*].role_arn)
    malware_protection_plan_arn = module.files_buckets.malware_protection_plan_arn
    flow_log_bucket_arn         = aws_s3_bucket.flow_logs.arn
  }
}

output "break_glass" {
  description = "The break-glass database role sft-<env>-break-glass-db and this Region's alert topic (#232)."
  value = {
    role_arn        = module.break_glass_role.role_arn
    alert_topic_arn = module.break_glass_role.alert_topic_arn
  }
}
