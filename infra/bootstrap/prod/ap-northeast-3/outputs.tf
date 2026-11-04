output "state_bucket_name" {
  description = "State bucket for this account in Osaka, for -backend-config=bucket=... ."
  value       = module.state.bucket_name
}

output "tfstate_key_arn" {
  description = "ARN of the Osaka replica of the tfstate key."
  value       = module.state.kms_key_arn
}
