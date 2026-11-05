output "key_arns" {
  description = "ARN of each class's key in this Region, by class. In Osaka these are the replicas."
  value       = local.key_arns
}

output "osaka_key_arns" {
  description = "Tokyo only: the ARN each key's Osaka replica has, or will have once the Osaka stack makes it. A replica keeps its primary's key ID. Empty where nothing replicates."
  value = (
    local.primary && var.osaka_replicas
    ? { for c, arn in local.key_arns : c => replace(arn, ":ap-northeast-1:", ":ap-northeast-3:") }
    : {}
  )
}

output "alias_names" {
  description = "Alias of each class's key, alias/sft/<env>/<class>, the same in both Regions."
  value       = { for c, a in aws_kms_alias.this : c => a.name }
}
