# The sign-in triggers' function, role and network (#238), planned against a mocked AWS provider
# (infra/scripts/check.sh test). Running against Cognito is pending the AWS run.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_data "aws_vpc" {
    defaults = { id = "vpc-0testonly", cidr_block = "10.10.0.0/16" }
  }
  mock_data "aws_subnets" {
    defaults = { ids = ["subnet-0testb", "subnet-0testa"] }
  }
  mock_data "aws_security_group" {
    defaults = { id = "sg-0endpoints" }
  }
  mock_data "aws_kms_alias" {
    defaults = { target_key_arn = "arn:aws:kms:ap-northeast-1:aws:key/test-only" }
  }
}

variables {
  environment      = "staging"
  account_id       = format("%012d", 1) # a placeholder account, never a real one
  region           = "ap-northeast-1"
  name_prefix      = "sft-staging-apne1"
  kms_alias_prefix = "alias/sft-staging"
  create_role      = true
  regions          = ["ap-northeast-1", "ap-northeast-3"]
  image_uri        = "registry.test/sft/app@sha256:${join("", [for i in range(64) : "a"])}"
  user_pool_arn    = "arn:aws:cognito-idp:ap-northeast-1:aws:userpool/ap-northeast-1_testonly"
  valkey = {
    cache_arn         = "arn:aws:elasticache:ap-northeast-1:aws:serverlesscache:sft-staging-apne1-valkey"
    address           = "sft-staging-apne1-valkey.serverless.apne1.cache.amazonaws.com"
    port              = 6379
    security_group_id = "sg-0valkey"
  }
}

run "function" {
  command = plan

  assert {
    condition = (
      aws_lambda_function.this.function_name == "sft-staging-apne1-signin-trigger" &&
      aws_lambda_function.this.package_type == "Image" &&
      aws_lambda_function.this.timeout == 5 &&
      tolist(aws_lambda_function.this.architectures) == tolist(["arm64"])
    )
    error_message = "One function, the API image, 5 seconds: Cognito's limit for a trigger."
  }

  assert {
    condition     = tolist(aws_lambda_function.this.image_config[0].entry_point) == tolist(["python", "-m", "sft.workers.signin_trigger"])
    error_message = "The function runs the triggers' entry point of the API image."
  }

  assert {
    condition = aws_lambda_function.this.environment[0].variables == tomap({
      LOG_LEVEL        = "info"
      VALKEY_URL       = "rediss://sft-staging-signin-trigger@sft-staging-apne1-valkey.serverless.apne1.cache.amazonaws.com:6379/0"
      VALKEY_IAM_CACHE = "sft-staging-apne1-valkey"
      SQS_QUEUE_PREFIX = "sft-staging-apne1-"
    })
    error_message = "Valkey over TLS as its own IAM user, and this Region's queues; no secret in the environment."
  }

  assert {
    condition     = toset(aws_lambda_function.this.vpc_config[0].subnet_ids) == toset(["subnet-0testa", "subnet-0testb"])
    error_message = "The function runs in the private subnets."
  }

  assert {
    condition = (
      aws_lambda_permission.user_pool.principal == "cognito-idp.amazonaws.com" &&
      aws_lambda_permission.user_pool.source_arn == var.user_pool_arn
    )
    error_message = "Only this Region's user pool may invoke the function."
  }

  assert {
    condition = (
      aws_vpc_security_group_egress_rule.valkey.referenced_security_group_id == "sg-0valkey" &&
      aws_vpc_security_group_egress_rule.valkey.from_port == 6379 &&
      aws_vpc_security_group_egress_rule.endpoints.referenced_security_group_id == "sg-0endpoints" &&
      aws_vpc_security_group_egress_rule.endpoints.from_port == 443 &&
      aws_vpc_security_group_ingress_rule.valkey_from_triggers.security_group_id == "sg-0valkey"
    )
    error_message = "Out only to the interface endpoints (443) and the counter store (6379), which admits it."
  }

  assert {
    condition     = aws_cloudwatch_log_group.this.retention_in_days == 90 && aws_cloudwatch_log_group.this.kms_key_id != null
    error_message = "Its logs are kept 90 days, encrypted with the logs key."
  }
}

run "role" {
  command = plan

  assert {
    condition     = aws_iam_role.this[0].name == "sft-staging-signin-trigger"
    error_message = "Tokyo makes the global role the queues, keys and Valkey users already name."
  }

  assert {
    condition = toset([for s in data.aws_iam_policy_document.this[0].statement : s.sid]) == toset([
      "SendSignInEvents", "PlatformKeyThroughSqs", "CounterStoreAsItsOwnUser", "ItsOwnLogs", "ItsNetworkInterfaces",
    ])
    error_message = "The role may send sign-in events, use the counter store, log and manage its interfaces; nothing else."
  }

  assert {
    condition = toset(flatten([
      for s in data.aws_iam_policy_document.this[0].statement : s.resources if s.sid == "SendSignInEvents"
      ])) == toset([
      "arn:aws:sqs:ap-northeast-1:${var.account_id}:sft-staging-apne1-signin-events",
      "arn:aws:sqs:ap-northeast-3:${var.account_id}:sft-staging-apne3-signin-events",
    ])
    error_message = "It may send to both Regions' signin-events queues and no other queue."
  }

  assert {
    condition = alltrue(flatten([
      for s in data.aws_iam_policy_document.this[0].statement : [
        for a in s.actions : !contains(["sqs:ReceiveMessage", "sqs:DeleteMessage", "elasticache:*", "*"], a)
      ]
    ]))
    error_message = "It can't read the queue or do more than connect to the cache."
  }
}

run "osaka_uses_tokyos_role" {
  command = plan

  variables {
    region      = "ap-northeast-3"
    name_prefix = "sft-staging-apne3"
    create_role = false
  }

  assert {
    condition     = length(aws_iam_role.this) == 0 && aws_lambda_function.this.role == "arn:aws:iam::${var.account_id}:role/sft-staging-signin-trigger"
    error_message = "Osaka's function uses the global role Tokyo's stack makes."
  }
}

run "image_by_digest_only" {
  command = plan

  variables {
    image_uri = "registry.test/sft/app:latest"
  }

  expect_failures = [var.image_uri]
}
