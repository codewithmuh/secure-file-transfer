# sft-<env>-events-delivery: the execution role EventBridge rules deliver through, into our queues and topics
# (encryption 4.4, threat model T-50). A key policy can't limit a bare events.amazonaws.com statement to our rules
# when it delivers to an encrypted topic, so the platform key names this role instead, and the role's trust names our
# rules. Its first rule is GuardDuty's scan results (ADR-0019); the SES tenant pauses and the security alerts use it
# too. It may send only to the queues that name it as their sender: guardduty-results and ses-tenant-status
# (modules/queues) and Karpenter's interruption queue (modules/eks-cluster, #103), which modules/data-stack passes in.
# IAM is global, so the Tokyo data stack makes it for both Regions.

locals {
  region_short = { "ap-northeast-1" = "apne1", "ap-northeast-3" = "apne3" }

  rule_arns = [for r in var.regions : "arn:aws:events:${r}:${var.account_id}:rule/sft-${var.environment}-*"]

  # Exactly the queues whose policy admits this role as their one sender (modules/queues), in each Region:
  # sft-<env>-<region-short>-<queue>. Any other queue's policy would deny it anyway; this keeps the two in step.
  queue_arns = flatten([
    for r in var.regions : [
      for q in var.queue_names : "arn:aws:sqs:${r}:${var.account_id}:sft-${var.environment}-${local.region_short[r]}-${q}"
    ]
  ])

  # The alert topics come with later issues, so every sft-<env>- topic for now.
  topic_arns = [for r in var.regions : "arn:aws:sns:${r}:${var.account_id}:sft-${var.environment}-*"]
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
  name                 = "sft-${var.environment}-events-delivery"
  description          = "EventBridge delivery into sft-${var.environment} queues and topics (encryption 4.4)."
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
