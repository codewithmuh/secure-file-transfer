# The SQS queues of ADR-0013 for one Region, each with its dead-letter queue: standard queues, SSE-KMS with the
# platform key, 20-second long polling, and a queue policy that lets only the queue's one sender send (T-50). Osaka has
# the same queues, idle until a failover (architecture 3.2).
#
# Fair queues need no setting: SQS schedules a standard queue fairly when the sender gives a MessageGroupId, and the
# outbox relay gives the tenant ID on the scan queues (ADR-0013, abuse 6.4).

locals {
  # Every queue of ADR-0013: its sender (T-50) and its starting visibility timeout, which the owning worker tunes, here
  # and in local/elasticmq/elasticmq.conf. A large scan extends its timeout as a heartbeat while it runs.
  queues = {
    # Work queues, fed only by the outbox relay.
    "scan-small" = { visibility_timeout_seconds = 60, role_arn = var.senders.relay_role_arn, topic_arn = null }
    "scan-large" = { visibility_timeout_seconds = 180, role_arn = var.senders.relay_role_arn, topic_arn = null }
    "notify"     = { visibility_timeout_seconds = 30, role_arn = var.senders.relay_role_arn, topic_arn = null }

    # Intake queues, one sender each: the sign-in triggers, the SES events topic, and EventBridge's delivery role for
    # GuardDuty results and SES tenant status.
    "signin-events"     = { visibility_timeout_seconds = 30, role_arn = var.senders.signin_trigger_role_arn, topic_arn = null }
    "ses-events"        = { visibility_timeout_seconds = 30, role_arn = null, topic_arn = var.senders.ses_events_topic_arn }
    "guardduty-results" = { visibility_timeout_seconds = 30, role_arn = var.senders.events_delivery_role_arn, topic_arn = null }
    "ses-tenant-status" = { visibility_timeout_seconds = 30, role_arn = var.senders.events_delivery_role_arn, topic_arn = null }
  }

  # Role senders are matched by aws:PrincipalArn, so a role that doesn't exist yet (the cluster layer makes the
  # workload roles after this one) is no error. A topic sends as sns.amazonaws.com and is matched by aws:SourceArn.
  role_senders  = { for k, q in local.queues : k => q.role_arn if q.role_arn != null }
  topic_senders = { for k, q in local.queues : k => q.topic_arn if q.topic_arn != null }
}

resource "aws_sqs_queue" "dead_letter" {
  for_each = local.queues

  name                              = "${var.name_prefix}-${each.key}-dlq"
  message_retention_seconds         = var.dead_letter_retention_seconds
  receive_wait_time_seconds         = 20
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "this" {
  for_each = local.queues

  name                              = "${var.name_prefix}-${each.key}"
  visibility_timeout_seconds        = each.value.visibility_timeout_seconds
  message_retention_seconds         = var.message_retention_seconds
  receive_wait_time_seconds         = 20
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter[each.key].arn
    maxReceiveCount     = var.max_receive_count
  })
}

# Each dead-letter queue takes messages from its own queue only.
resource "aws_sqs_queue_redrive_allow_policy" "dead_letter" {
  for_each = local.queues

  queue_url = aws_sqs_queue.dead_letter[each.key].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.this[each.key].arn]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# Queue policies. Deny statements do the work, so an identity policy with sqs:SendMessage on * can't reach a queue:
# every principal but the named sender is denied SendMessage (which also covers SendMessageBatch), and every request
# without TLS is denied (encryption 2.2).
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "queue" {
  for_each = local.queues

  statement {
    sid       = "DenyWithoutTls"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.this[each.key].arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = contains(keys(local.role_senders), each.key) ? [local.role_senders[each.key]] : []

    content {
      sid       = "DenySendExceptItsSender"
      effect    = "Deny"
      actions   = ["sqs:SendMessage"]
      resources = [aws_sqs_queue.this[each.key].arn]

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values   = [statement.value]
      }
    }
  }

  # A topic delivers as the SNS service, which needs the queue policy's allow.
  dynamic "statement" {
    for_each = contains(keys(local.topic_senders), each.key) ? [local.topic_senders[each.key]] : []

    content {
      sid       = "AllowItsTopic"
      effect    = "Allow"
      actions   = ["sqs:SendMessage"]
      resources = [aws_sqs_queue.this[each.key].arn]

      principals {
        type        = "Service"
        identifiers = ["sns.amazonaws.com"]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = [statement.value]
      }
    }
  }

  # Requests by IAM principals carry no aws:SourceArn, so this denies them all, as well as any other topic.
  dynamic "statement" {
    for_each = contains(keys(local.topic_senders), each.key) ? [local.topic_senders[each.key]] : []

    content {
      sid       = "DenySendExceptItsTopic"
      effect    = "Deny"
      actions   = ["sqs:SendMessage"]
      resources = [aws_sqs_queue.this[each.key].arn]

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnNotEquals"
        variable = "aws:SourceArn"
        values   = [statement.value]
      }
    }
  }
}

resource "aws_sqs_queue_policy" "this" {
  for_each = local.queues

  queue_url = aws_sqs_queue.this[each.key].id
  policy    = data.aws_iam_policy_document.queue[each.key].json
}

# Only SQS itself moves messages into a dead-letter queue, so nobody may send to one.
data "aws_iam_policy_document" "dead_letter" {
  for_each = local.queues

  statement {
    sid       = "DenyWithoutTls"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.dead_letter[each.key].arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyAllSends"
    effect    = "Deny"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dead_letter[each.key].arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_sqs_queue_policy" "dead_letter" {
  for_each = local.queues

  queue_url = aws_sqs_queue.dead_letter[each.key].id
  policy    = data.aws_iam_policy_document.dead_letter[each.key].json
}
