output "json" {
  description = "The key policy, as JSON."
  value       = data.aws_iam_policy_document.this.json
}
