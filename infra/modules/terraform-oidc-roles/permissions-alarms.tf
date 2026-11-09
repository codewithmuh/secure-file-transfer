# ---------------------------------------------------------------------------------------------------------------------
# Alarms layer (#246): what modules/alarms needs in the Regions of var.network_regions, plus us-east-1 for the Route 53
# health check alarms, their two topics and their key (NFR-21's exception; SCP 1 allows CloudWatch, SNS and KMS there).
# The plan role reads (`sft-<env>-terraform-alarms-read`); the deploy role's one policy (`-alarms`) holds the same
# reads and also creates, changes and deletes.
#
# - CloudWatch: alarms named sft-<env>-* only, which SCP 3 also keeps with the apply roles.
# - SNS: the topics sft-<env>-<rs>-alerts-page, -alerts-ticket, -heartbeat and -region-health-*, and subscriptions on
#   them and on the break-glass alert topics. Each topic's own policy then denies changes to everyone but this role.
# - KMS: creating the us-east-1 key and its alias; the key's own policy then makes this role its administrator
#   (modules/key-policy). Aliases need both.
# - EC2: listing the NAT gateways the NAT alarms watch.
#
# The deploy role's thirteenth managed policy and the plan role's seventh, within the raised quota of 20 (infra/README.md,
# "IAM quotas").
# ---------------------------------------------------------------------------------------------------------------------

locals {
  alarms_enabled = local.network_enabled

  alarms_regions = concat(var.network_regions, ["us-east-1"])

  alarms_alarm_arns = [for r in local.alarms_regions : "arn:aws:cloudwatch:${r}:${var.account_id}:alarm:${local.cluster_env_prefix}-*"]

  alarms_topics = concat(
    flatten([
      for r in var.network_regions : [
        for t in ["alerts-page", "alerts-ticket", "heartbeat"] :
        "arn:aws:sns:${r}:${var.account_id}:${local.cluster_env_prefix}-${local.identity_region_shorts[r]}-${t}"
      ]
    ]),
    ["arn:aws:sns:us-east-1:${var.account_id}:${local.cluster_env_prefix}-apne1-region-health-*"],
  )

  # Subscriptions are made on the alarm topics and the break-glass topics; a subscription's ARN is its topic's plus an ID.
  alarms_subscribed_topics = concat(local.alarms_topics, local.break_glass_topics)
}

data "aws_iam_policy_document" "alarms_read" {
  count = local.alarms_enabled ? 1 : 0

  statement {
    sid       = "AlarmsRead"
    actions   = ["cloudwatch:DescribeAlarms", "cloudwatch:ListTagsForResource"]
    resources = local.alarms_alarm_arns
  }

  statement {
    sid = "AlarmTopicsRead"
    actions = [
      "sns:GetSubscriptionAttributes", "sns:GetTopicAttributes", "sns:ListSubscriptionsByTopic",
      "sns:ListTagsForResource",
    ]
    resources = concat(local.alarms_subscribed_topics, [for t in local.alarms_subscribed_topics : "${t}:*"])
  }

  statement {
    sid       = "NatGatewaysAndKeysList"
    actions   = ["ec2:DescribeNatGateways", "kms:ListAliases"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = local.alarms_regions
    }
  }

  # The promotion gate reads the synthetic probe's result (SecureFileTransfer/Probe ProbeSuccess) as this account's
  # plan role (.github/workflows/promote.yml, #247). GetMetricData can't be scoped to a namespace or a metric; the
  # metrics hold no tenant data, and the plan role trusts pull requests only (T-71).
  statement {
    sid       = "ProbeResultRead"
    actions   = ["cloudwatch:GetMetricData"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-northeast-1"]
    }
  }
}

data "aws_iam_policy_document" "alarms" {
  count = local.alarms_enabled && var.github_environment != null ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.alarms_read[0].json]

  statement {
    sid = "AlarmsOnly"
    actions = [
      "cloudwatch:DeleteAlarms", "cloudwatch:PutMetricAlarm", "cloudwatch:TagResource", "cloudwatch:UntagResource",
    ]
    resources = local.alarms_alarm_arns
  }

  statement {
    sid = "AlarmTopicsOnly"
    actions = [
      "sns:CreateTopic", "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:TagResource", "sns:UntagResource",
    ]
    resources = local.alarms_topics
  }

  statement {
    sid       = "SubscriptionsOnly"
    actions   = ["sns:SetSubscriptionAttributes", "sns:Subscribe", "sns:Unsubscribe"]
    resources = concat(local.alarms_subscribed_topics, [for t in local.alarms_subscribed_topics : "${t}:*"])
  }

  statement {
    sid       = "UsEast1Key"
    actions   = ["kms:CreateAlias", "kms:CreateKey", "kms:DeleteAlias", "kms:TagResource"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = ["us-east-1"]
    }
  }
}

resource "aws_iam_policy" "alarms_read" {
  count = local.alarms_enabled ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-alarms-read"
  path        = var.iam_path
  description = "Terraform plan: read the alarms layer's alarms, topics and subscriptions (#246)."
  policy      = data.aws_iam_policy_document.alarms_read[0].json
}

resource "aws_iam_role_policy_attachment" "plan_alarms" {
  count = local.alarms_enabled ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.alarms_read[0].arn
}

resource "aws_iam_policy" "alarms" {
  count = local.alarms_enabled && var.github_environment != null ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-alarms"
  path        = var.iam_path
  description = "Terraform deploy: the alarms layer's alarms, topics, subscriptions and us-east-1 key (#246)."
  policy      = data.aws_iam_policy_document.alarms[0].json
}

resource "aws_iam_role_policy_attachment" "deploy_alarms" {
  count = local.alarms_enabled && var.github_environment != null ? 1 : 0

  role       = aws_iam_role.deploy[0].name
  policy_arn = aws_iam_policy.alarms[0].arn
}
