output "bucket_name" {
  description = "Name of the archive bucket in this Region: sft-<env>-<region-short>-audit-archive-<account-id>."
  value       = local.bucket_id
}

output "bucket_arn" {
  description = "ARN of the archive bucket in this Region. Environment stacks refer to the prod archive only by it (encryption 8.4)."
  value       = "arn:aws:s3:::${local.bucket_id}"
}

output "replication_role_arn" {
  description = "ARN of the role that replicates this archive to Osaka, or null where nothing replicates."
  value       = local.replication_policy ? local.replication_role_arn : null
}
