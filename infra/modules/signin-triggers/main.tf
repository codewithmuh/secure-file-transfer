# The Cognito sign-in triggers (#238; ADR-0016, consequences; authn and authz 2.4; abuse and rate limits 2.3): one
# Lambda function for the pre- and post-authentication triggers of this Region's user pool. It runs the API image
# (sft.workers.signin_trigger, which speaks the Lambda Runtime API itself) in the private subnets, and reaches only the
# counter store, where it counts each account's failed sign-ins, and the signin-events queue, which carries every
# attempt and success to the audit log. When it can reach neither, it denies the sign-in.
#
# - The role is sft-<env>-signin-trigger, global, made by Tokyo's stack (create_role) and used in both Regions: the
#   queues' policies (modules/queues), the platform key's policy (modules/kms-keys) and the Valkey users
#   (modules/valkey) already name it. It may send to the signin-events queues, connect to the caches as its own
#   Valkey user, write its own log group and manage its network interfaces in this VPC; nothing else.
# - Its security group allows out only HTTPS to the private subnets' interface endpoints (SQS, KMS, STS) and 6379 to
#   the counter store, whose group this stack opens to it. The private subnets' NAT route is closed to it by the
#   network's design (modules/network, security-groups.tf): only the system nodes' group may leave the VPC.
# - Cognito answers a trigger within 5 seconds, so the function has 5 seconds; a cold start in the VPC fits.
# - Only this Region's user pool may invoke it.

data "aws_vpc" "this" {
  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.this.id]
  }

  tags = {
    tier = "private"
  }
}

# The interface endpoints' group (modules/network), which admits HTTPS from the private subnets.
data "aws_security_group" "endpoints" {
  vpc_id = data.aws_vpc.this.id
  name   = "${var.name_prefix}-endpoints"
}

data "aws_kms_alias" "logs" {
  name = "${var.kms_alias_prefix}/logs"
}

locals {
  env_prefix    = "sft-${var.environment}"
  role_name     = var.conventions.workload_role_names["signin-trigger"]
  role_arn      = "arn:aws:iam::${var.account_id}:role/${local.role_name}"
  function_name = "${var.name_prefix}-signin-trigger"
  region_short  = var.conventions.region_shorts

  # Every Region's resources by name, so one global role serves both Regions' functions.
  queue_arns = [
    for r in var.regions : "arn:aws:sqs:${r}:${var.account_id}:${local.env_prefix}-${local.region_short[r]}-signin-events"
  ]
  cache_arns = [
    for r in var.regions : "arn:aws:elasticache:${r}:${var.account_id}:serverlesscache:${local.env_prefix}-${local.region_short[r]}-valkey"
  ]
  valkey_user_arns = [for r in var.regions : "arn:aws:elasticache:${r}:${var.account_id}:user:${local.role_name}"]
  log_group_arns = [
    for r in var.regions : "arn:aws:logs:${r}:${var.account_id}:log-group:/aws/lambda/${local.env_prefix}-${local.region_short[r]}-signin-trigger:*"
  ]

  cache_name = element(split(":", var.valkey.cache_arn), 6)
}

# --- Role -----------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "trust" {
  count = var.create_role ? 1 : 0

  statement {
    sid     = "TheTriggerFunctionsOnly"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "this" {
  count = var.create_role ? 1 : 0

  name                 = local.role_name
  description          = "The Cognito sign-in triggers of sft-${var.environment} (#238): counter store and signin-events only."
  assume_role_policy   = data.aws_iam_policy_document.trust[0].json
  max_session_duration = 3600

  tags = { component = "identity" }
}

data "aws_iam_policy_document" "this" {
  count = var.create_role ? 1 : 0

  statement {
    sid       = "SendSignInEvents"
    actions   = ["sqs:SendMessage", "sqs:GetQueueUrl"]
    resources = local.queue_arns
  }

  # The queues are encrypted with the platform key, whose policy names this role for signin-events (modules/kms-keys).
  statement {
    sid       = "PlatformKeyThroughSqs"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["arn:aws:kms:*:${var.account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = ["alias/${local.env_prefix}/platform"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in var.regions : "sqs.${r}.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:sqs:arn"
      values   = local.queue_arns
    }
  }

  # IAM authentication to Valkey as its own user only (ADR-0014).
  statement {
    sid       = "CounterStoreAsItsOwnUser"
    actions   = ["elasticache:Connect"]
    resources = concat(local.cache_arns, local.valkey_user_arns)
  }

  statement {
    sid       = "ItsOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = local.log_group_arns
  }

  # A function in a VPC manages its own network interfaces. EC2 checks these against the account, not an ENI ARN, so
  # they take every resource, held to this account's Regions.
  statement {
    sid = "ItsNetworkInterfaces"
    actions = [
      "ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface",
      "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses", "ec2:DescribeSubnets", "ec2:DescribeVpcs",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.regions
    }
  }
}

resource "aws_iam_role_policy" "this" {
  count = var.create_role ? 1 : 0

  name   = "signin-trigger"
  role   = aws_iam_role.this[0].id
  policy = data.aws_iam_policy_document.this[0].json
}

# --- Network --------------------------------------------------------------------------------------------------------

resource "aws_security_group" "this" {
  name        = local.function_name
  description = "Cognito sign-in triggers: HTTPS to the interface endpoints and 6379 to the counter store only (#238)"
  vpc_id      = data.aws_vpc.this.id

  tags = {
    Name = local.function_name
  }
}

resource "aws_vpc_security_group_egress_rule" "endpoints" {
  security_group_id            = aws_security_group.this.id
  description                  = "HTTPS to the interface endpoints: SQS, KMS and STS"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = data.aws_security_group.endpoints.id
}

resource "aws_vpc_security_group_egress_rule" "valkey" {
  security_group_id            = aws_security_group.this.id
  description                  = "The counter store"
  ip_protocol                  = "tcp"
  from_port                    = var.valkey.port
  to_port                      = var.valkey.port
  referenced_security_group_id = var.valkey.security_group_id
}

resource "aws_vpc_security_group_ingress_rule" "valkey_from_triggers" {
  security_group_id            = var.valkey.security_group_id
  description                  = "Valkey from the Cognito sign-in triggers (#238)"
  ip_protocol                  = "tcp"
  from_port                    = var.valkey.port
  to_port                      = var.valkey.port
  referenced_security_group_id = aws_security_group.this.id
}

# --- Function -------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = data.aws_kms_alias.logs.target_key_arn

  tags = { component = "identity" }
}

resource "aws_lambda_function" "this" {
  function_name = local.function_name
  description   = "Cognito pre- and post-authentication triggers: failed sign-ins per account and the sign-in audit (#238)."
  role          = local.role_arn
  package_type  = "Image"
  image_uri     = var.image_uri
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 5

  image_config {
    entry_point = ["python", "-m", "sft.workers.signin_trigger"]
    command     = []
  }

  vpc_config {
    subnet_ids         = sort(data.aws_subnets.private.ids)
    security_group_ids = [aws_security_group.this.id]
  }

  environment {
    variables = {
      LOG_LEVEL        = "info"
      VALKEY_URL       = "rediss://${local.role_name}@${var.valkey.address}:${var.valkey.port}/0"
      VALKEY_IAM_CACHE = local.cache_name
      SQS_QUEUE_PREFIX = "${var.name_prefix}-"
    }
  }

  tracing_config {
    mode = "PassThrough"
  }

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.this.name
  }

  tags = { component = "identity" }

  lifecycle {
    precondition {
      # The global role names each Region's queue, cache and log group: this stack's Region must be one of them.
      condition     = contains(var.regions, var.region)
      error_message = "region must be one of regions, whose resources the trigger role may reach."
    }
  }

  depends_on = [aws_iam_role_policy.this, aws_cloudwatch_log_group.this]
}

resource "aws_lambda_permission" "user_pool" {
  statement_id   = "CognitoUserPoolOnly"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.this.function_name
  principal      = "cognito-idp.amazonaws.com"
  source_arn     = var.user_pool_arn
  source_account = var.account_id
}
