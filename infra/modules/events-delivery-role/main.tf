# sft-<env>-events-delivery: the execution role EventBridge rules deliver through, into our queues and topics
# (encryption 4.4, threat model T-50). A key policy can't limit a bare events.amazonaws.com statement to our rules
# when it delivers to an encrypted topic, so the platform key names this role instead, and the role's trust names our
# rules. Its first rule is GuardDuty's scan results (ADR-0019); the SES tenant pauses and the security alerts use it
# too (#256), and so do the us-east-1 rules that forward global sign-in and STS events to a Region's default event bus,
# where the security alert rules see them. It may send only to the queues that name it as their sender: guardduty-results and ses-tenant-status
# (modules/queues) and Karpenter's interruption queue (modules/eks-cluster, #103), which modules/data-stack passes in.
# IAM is global, so the Tokyo data stack makes it for both Regions.

locals {
  region_short = var.conventions.region_shorts
  env_prefix   = var.conventions.global_name_prefix

  # Our rules in our Regions, and in us-east-1, where IAM, root and global STS sign-in events arrive (#256).
  rule_arns = [for r in concat(var.regions, ["us-east-1"]) : "arn:aws:events:${r}:${var.account_id}:rule/${local.env_prefix}-*"]

  # Exactly the queues whose policy admits this role as their one sender (modules/queues), in each Region:
  # sft-<env>-<region-short>-<queue>. Any other queue's policy would deny it anyway; this keeps the two in step.
  queue_arns = flatten([
    for r in var.regions : [
      for q in var.queue_names : "arn:aws:sqs:${r}:${var.account_id}:${local.env_prefix}-${local.region_short[r]}-${q}"
    ]
  ])

  # The alert topics: the page topics (modules/alarms) and the break-glass topics, all sft-<env>-*.
  topic_arns = [for r in var.regions : "arn:aws:sns:${r}:${var.account_id}:${local.env_prefix}-*"]

  # The Regions' default event buses, which the us-east-1 forwarding rules put events on (#256).
  event_bus_arns = [for r in var.regions : "arn:aws:events:${r}:${var.account_id}:event-bus/default"]
}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "OurRulesOnly"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = local.rule_arns
    }
  }
}

resource "aws_iam_role" "this" {
  name                 = var.conventions.workload_role_names["events-delivery"]
  description          = "EventBridge delivery into ${local.env_prefix} queues, topics and event buses (encryption 4.4)."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600

  # The workload boundary every role the cluster deploy role may pass carries (terraform-oidc-roles,
  # permissions-cluster.tf): no IAM change, no sts:AssumeRole, only the services the platform uses.
  permissions_boundary = var.permissions_boundary_arn

  tags = { component = "events" }
}

data "aws_iam_policy_document" "deliver" {
  statement {
    sid       = "SendToOurQueues"
    actions   = ["sqs:SendMessage"]
    resources = local.queue_arns
  }

  statement {
    sid       = "PublishToOurTopics"
    actions   = ["sns:Publish"]
    resources = local.topic_arns
  }

  # The us-east-1 rules forward global events to our Regions' default buses (#256); the same account, so no bus policy.
  statement {
    sid       = "ForwardToOurDefaultBuses"
    actions   = ["events:PutEvents"]
    resources = local.event_bus_arns
  }

  # The platform key, through SQS and SNS only; its key policy repeats the condition.
  statement {
    sid       = "UseThePlatformKeyThroughSqsAndSns"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = var.platform_key_arns

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = flatten([
        for r in var.regions : ["sqs.${r}.amazonaws.com", "sns.${r}.amazonaws.com"]
      ])
    }
  }
}

resource "aws_iam_role_policy" "deliver" {
  name   = "deliver"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.deliver.json
}
