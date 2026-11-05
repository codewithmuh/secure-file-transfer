output "bucket_name" {
  description = "Name of the log archive bucket."
  value       = aws_s3_bucket.archive.id
}

output "bucket_arn" {
  description = "ARN of the log archive bucket, for the environments' trails."
  value       = aws_s3_bucket.archive.arn
}

output "logs_key_arn" {
  description = "ARN of the shared account's logs key, which the environments' trails name."
  value       = aws_kms_key.logs.arn
}

output "trail_arn" {
  description = "ARN of the organization trail."
  value       = aws_cloudtrail.organization.arn
}
