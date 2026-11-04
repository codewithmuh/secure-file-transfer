output "user_arn" {
  description = "ARN of the emergency user. In staging and prod, Osaka's state bucket and tfstate key name it exactly."
  value       = aws_iam_user.emergency.arn
}
