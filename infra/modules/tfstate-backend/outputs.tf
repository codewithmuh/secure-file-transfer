output "bucket_name" {
  description = "Name of the state bucket, for -backend-config=bucket=... in this account and Region."
  value       = aws_s3_bucket.state.bucket
}

output "bucket_arn" {
  description = "ARN of the state bucket."
  value       = aws_s3_bucket.state.arn
}

output "kms_key_arn" {
  description = "ARN of the tfstate key in this Region. Osaka's bootstrap stack replicates Tokyo's."
  value       = local.key_arn
}

output "kms_alias_name" {
  description = "Alias of the tfstate key."
  value       = aws_kms_alias.state.name
}
