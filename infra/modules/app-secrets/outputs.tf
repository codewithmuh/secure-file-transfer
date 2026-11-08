output "secret_arns" {
  description = "Each secret by its name under sft/<env>/app/: the keyrings (Tokyo) and this Region's idp-client."
  value = merge(
    { for k, s in aws_secretsmanager_secret.keyring : k => s.arn },
    { "idp-client/${var.region}" = aws_secretsmanager_secret.idp_client.arn },
  )
}
