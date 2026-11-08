output "user_pool_id" {
  description = "This Region's user pool: cluster-bootstrap's cognito_user_pool_id."
  value       = module.user_pool.user_pool_id
}

output "user_pool_arn" {
  description = "This Region's user pool, for IAM statements."
  value       = module.user_pool.user_pool_arn
}

output "cognito_login_domain" {
  description = "The pool's managed login domain: cluster-bootstrap's cognito_login_domain."
  value       = module.user_pool.login_domain
}

output "app_client_id" {
  description = "The API's app client; its secret is written by the key rotation job, never output."
  value       = module.user_pool.client_id
}

output "ses_configuration_set" {
  description = "This Region's configuration set: the notification worker's SES_CONFIGURATION_SET."
  value       = module.ses.configuration_set
}

output "mail_from_address" {
  description = "no-reply@mail.<service domain>."
  value       = module.ses.from_address
}

output "secret_arns" {
  description = "The application's secrets in this Region, by name under sft/<env>/app/."
  value       = module.app_secrets.secret_arns
}
