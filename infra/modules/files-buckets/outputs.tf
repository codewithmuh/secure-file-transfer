output "bucket_names" {
  description = "Bucket names by kind: files (up to 2 GB) and large-files."
  value       = { for k, b in aws_s3_bucket.this : k => b.id }
}

output "bucket_arns" {
  description = "Bucket ARNs by kind: files and large-files."
  value       = { for k, b in aws_s3_bucket.this : k => b.arn }
}

output "replication_role_arn" {
  description = "Tokyo, staging and prod: ARN of sft-<env>-s3-replication. Null elsewhere."
  value       = one(aws_iam_role.replication[*].arn)
}

output "replication_role_name" {
  description = "Tokyo, staging and prod: name of the replication role, which the audit archive module adds its policy to. Null elsewhere."
  value       = one(aws_iam_role.replication[*].name)
}

output "malware_protection_plan_arn" {
  description = "ARN of the large-files bucket's GuardDuty Malware Protection plan, or null where it is off."
  value       = one(aws_guardduty_malware_protection_plan.large_files[*].arn)
}
