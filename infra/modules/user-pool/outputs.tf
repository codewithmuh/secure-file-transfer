output "user_pool_id" {
  description = "The pool's ID: cluster-bootstrap's cognito_user_pool_id, the API's OIDC_PROVIDER_NAME, the worker's COGNITO_USER_POOL_ID."
  value       = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  description = "The pool, for the notification worker's and the key rotation job's IAM statements."
  value       = aws_cognito_user_pool.this.arn
}

output "login_domain" {
  description = "The managed login domain, <prefix>.auth.<region>.amazoncognito.com: cluster-bootstrap's cognito_login_domain."
  value       = "${aws_cognito_user_pool_domain.this.domain}.auth.${var.region}.amazoncognito.com"
}

output "client_id" {
  description = "The API's app client. Its secret is never an output: the key rotation job writes it to sft/<env>/app/idp-client/<region>."
  value       = aws_cognito_user_pool_client.api.id
}
