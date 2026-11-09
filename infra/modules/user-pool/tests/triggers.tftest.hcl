# The user pool names the sign-in triggers' function for both triggers (#238; authn and authz 9.2, "both triggers
# attached"). Planned against a mocked AWS provider (infra/scripts/check.sh test).

mock_provider "aws" {}

variables {
  environment           = "dev"
  account_id            = format("%012d", 1) # a placeholder account, never a real one
  region                = "ap-northeast-1"
  region_short          = "apne1"
  name_prefix           = "sft-dev-apne1"
  domain                = "example.com"
  ses_identity_arn      = "arn:aws:ses:ap-northeast-1:aws:identity/mail.dev.sft.example.com"
  from_address          = "no-reply@mail.dev.sft.example.com"
  ses_configuration_set = "sft-dev"
  deletion_protection   = false
  trigger_function_arn  = "arn:aws:lambda:ap-northeast-1:aws:function:sft-dev-apne1-signin-trigger"
}

run "both_triggers" {
  command = plan

  assert {
    condition = (
      aws_cognito_user_pool.this.lambda_config[0].pre_authentication == var.trigger_function_arn &&
      aws_cognito_user_pool.this.lambda_config[0].post_authentication == var.trigger_function_arn
    )
    error_message = "The pre- and post-authentication triggers are the sign-in triggers' function."
  }

  assert {
    condition     = aws_cognito_user_pool_client.api.prevent_user_existence_errors == "ENABLED"
    error_message = "The client prevents user existence errors, so the trigger sees unknown usernames too and tells nothing."
  }
}
