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
