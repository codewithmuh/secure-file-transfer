output "bucket_name" {
  description = "The bundle store: the WEB_BUNDLE_BUCKET repository variable of the web release workflows."
  value       = aws_s3_bucket.store.id
}

output "publish_role_arn" {
  description = "The web release workflow's publish role: the WEB_PUBLISH_ROLE_ARN repository variable."
  value       = aws_iam_role.publish.arn
}
