output "bucket_names" {
  description = "Loki's and Tempo's buckets in this Region, by store."
  value       = { for k, b in aws_s3_bucket.store : k => b.bucket }
}

output "role_arns" {
  description = "The observability roles by workload, bound to this Region's cluster through Pod Identity."
  value       = local.role_arns
}
