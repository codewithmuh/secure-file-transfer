output "audit_key_arns" {
  description = "The audit key: Tokyo's primary and Osaka's replica."
  value = {
    "ap-northeast-1" = module.audit_key.key_arns["audit"]
    "ap-northeast-3" = module.audit_key_osaka.key_arns["audit"]
  }
}

output "audit_archive_bucket_arns" {
  description = "The archive buckets, by Region. Environment stacks refer to the archive only by these (encryption 8.4)."
  value = {
    "ap-northeast-1" = module.audit_archive.bucket_arn
    "ap-northeast-3" = module.audit_archive_osaka.bucket_arn
  }
}

output "deploy_role_arn" {
  description = "sft-prod-retained-terraform-deploy: the role the prod-retained GitHub environment applies this stack with (#263)."
  value       = aws_iam_role.deploy.arn
}

output "state_bucket_name" {
  description = "This stack's own state bucket, under the audit key: -backend-config=\"bucket=...\" at init (#263)."
  value       = aws_s3_bucket.state.id
}

output "trail_arn" {
  description = "The retained trail: the archive's data events, and from teardown the account's management events (#263)."
  value       = aws_cloudtrail.retained.arn
}

output "alert_topic_arns" {
  description = "The retained alert topics, by Region (#263)."
  value = {
    (module.conventions.region) = aws_sns_topic.retained_tokyo.arn
    "ap-northeast-3"            = aws_sns_topic.retained_osaka.arn
  }
}
