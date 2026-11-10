output "bucket_name" {
  description = "The Region's mailbox bucket, sft-<env>-<region-short>-probe-mailbox-<account-id>: the probe's PROBE_MAILBOX_BUCKET, and LOADTEST_MAILBOX_BUCKET in staging."
  value       = aws_s3_bucket.this.id
}

output "mailbox_domains" {
  description = "The domains SES receives for here, by mailbox: probe.<service domain>, and loadtest.<service domain> in staging."
  value       = { for m, v in local.mailboxes : m => v.domain }
}

output "load_test_role_arn" {
  description = "staging only: sft-staging-loadtest, the loadtest workflow's LOADTEST_ROLE_ARN. Null elsewhere."
  value       = one(aws_iam_role.load_test[*].arn)
}
