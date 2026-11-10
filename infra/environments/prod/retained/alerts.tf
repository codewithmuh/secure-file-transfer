# The retained stack's alerts (encryption 8.4, #263): EventBridge rules in both Regions on the calls that could hurt
# the archive, into an alert topic in each Region under the audit key, through this stack's own delivery role,
# sft-prod-retained-events-delivery. They depend on nothing teardown removes, so they keep paging after prod is gone,
# when AWS Config and the environment's own security alerts (modules/alarms, #256) have gone with it.
#
# | Rule                                | Fires on                                                                       |
# |-------------------------------------|--------------------------------------------------------------------------------|
# | sft-prod-<rs>-retained-bucket-changed | A guard of an archive, state or trail bucket changed by anyone but this stack's |
# |                                     | deploy role, or any refused attempt                                            |
# | sft-prod-<rs>-retained-key-changed  | The audit key's policy, state or rotation changed by anyone but this stack's    |
# |                                     | deploy role, any refused attempt, and its disabling or deletion by anyone      |
# | sft-prod-apne1-retained-trail-changed | The retained trail, or these rules, changed by anyone but this stack's deploy |
# |                                     | role, or any refused attempt (Tokyo, the trail's home Region)                   |
#
# EventBridge sees CloudTrail's events only while a trail logs them: the organization trail while prod runs, this
# stack's own trail from the teardown apply on (trail.tf). While prod runs, a change to the audit key also pages
# through the environment's own kms-key-changed rule, to the environment's page topic: two pages, two topics.
# Who the topics reach is TF_VAR_alert_emails; each address confirms its subscription once.
#
# Any change to the SCPs is recorded in the management account, which this account's rules can't see; that alert
# belongs to the organization stack (a follow-up in docs/operations/disaster-recovery.md section 8).

locals {
  retained_events_delivery = "sft-prod-retained-events-delivery"
  retained_delivery_arn    = "arn:aws:iam::${var.account_id}:role/${local.retained_events_delivery}"

  retained_alert_regions = {
    (module.conventions.region) = { short = module.conventions.region_short, key = module.audit_key.key_arns["audit"] }
    "ap-northeast-3"            = { short = module.conventions.region_shorts["ap-northeast-3"], key = module.audit_key_osaka.key_arns["audit"] }
  }
  retained_topic_arns = {
    for r, v in local.retained_alert_regions : r => "arn:aws:sns:${r}:${var.account_id}:sft-prod-${v.short}-retained-alerts"
  }

  retained_runbook = "https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/retained-stack-change.md"

  # Anyone but this stack's deploy role, or a refused attempt.
  not_the_retained_deploy_role = [
    { userIdentity = { sessionContext = { sessionIssuer = { arn = [{ "anything-but" = [local.retained_deploy_role_arn] }] } } } },
    { userIdentity = { type = [{ "anything-but" = ["AssumedRole"] }] } },
    { errorCode = [{ exists = true }] },
  ]

  bucket_guard_events = [
    "DeleteBucket", "DeleteBucketEncryption", "DeleteBucketLifecycle", "DeleteBucketPolicy",
    "DeleteBucketPublicAccessBlock", "DeleteBucketReplication", "PutBucketEncryption", "PutBucketLifecycle",
    "PutBucketOwnershipControls", "PutBucketPolicy", "PutBucketPublicAccessBlock", "PutBucketReplication",
    "PutBucketVersioning", "PutObjectLockConfiguration",
  ]
  key_change_events = [
    "CancelKeyDeletion", "DisableKey", "DisableKeyRotation", "EnableKeyRotation", "PutKeyPolicy", "ReplicateKey",
    "RevokeGrant", "ScheduleKeyDeletion", "UpdatePrimaryRegion",
  ]

  retained_rules = merge(
    {
      for r, v in local.retained_alert_regions : "${r}/bucket-changed" => {
        region  = r
        name    = "sft-prod-${v.short}-retained-bucket-changed"
        alert   = "RetainedBucketChanged"
        summary = "A guard of the audit archive, or of the retained stack's state or trail bucket, was changed outside the retained stack, or someone tried (encryption 8.4)."
        pattern = {
          source        = ["aws.s3"]
          "detail-type" = ["AWS API Call via CloudTrail"]
          detail = {
            eventSource = ["s3.amazonaws.com"]
            eventName   = local.bucket_guard_events
            requestParameters = {
              bucketName = [
                { prefix = "sft-prod-${v.short}-audit-archive-" }, { prefix = "sft-prod-${v.short}-retained-" },
              ]
            }
            "$or" = local.not_the_retained_deploy_role
          }
        }
      }
    },
    {
      for r, v in local.retained_alert_regions : "${r}/key-changed" => {
        region  = r
        name    = "sft-prod-${v.short}-retained-key-changed"
        alert   = "RetainedKeyChanged"
        summary = "The audit key's policy, state or rotation was changed outside the retained stack, someone tried, or it was disabled or scheduled for deletion (encryption 8.4, T-61)."
        pattern = {
          source        = ["aws.kms"]
          "detail-type" = ["AWS API Call via CloudTrail"]
          detail = {
            eventSource = ["kms.amazonaws.com"]
            resources   = { ARN = [v.key] }
            "$or" = concat(
              [for who in local.not_the_retained_deploy_role : merge({ eventName = local.key_change_events }, who)],
              [{ eventName = ["DisableKey", "ScheduleKeyDeletion"] }],
            )
          }
        }
      }
    },
    {
      ("${module.conventions.region}/trail-changed") = {
        region  = module.conventions.region
        name    = "sft-prod-${module.conventions.region_short}-retained-trail-changed"
        alert   = "RetainedTrailChanged"
        summary = "The retained trail, or the retained stack's alert rules, were changed outside the retained stack, or someone tried (encryption 8.4, T-75)."
        pattern = {
          "detail-type" = ["AWS API Call via CloudTrail"]
          detail = {
            "$or" = concat(
              [
                for who in local.not_the_retained_deploy_role : merge({
                  eventSource       = ["cloudtrail.amazonaws.com"]
                  eventName         = ["DeleteTrail", "PutEventSelectors", "StopLogging", "UpdateTrail"]
                  requestParameters = { name = [{ suffix = local.trail_name }] }
                }, who)
              ],
              [
                for who in local.not_the_retained_deploy_role : merge({
                  eventSource       = ["events.amazonaws.com"]
                  eventName         = ["DeleteRule", "DisableRule", "PutRule"]
                  requestParameters = { name = [{ wildcard = "sft-prod-*-retained-*" }] }
                }, who)
              ],
            )
          }
        }
      }
    },
  )
}

# --- The delivery role ------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "retained_delivery_trust" {
  statement {
    sid     = "TheRetainedRulesOnly"
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
      values   = [for r in keys(local.retained_alert_regions) : "arn:aws:events:${r}:${var.account_id}:rule/sft-prod-*-retained-*"]
    }
  }
}

resource "aws_iam_role" "retained_delivery" {
  name                 = local.retained_events_delivery
  description          = "EventBridge delivery of the retained stack's alerts to its topics (encryption 8.4)."
  assume_role_policy   = data.aws_iam_policy_document.retained_delivery_trust.json
  max_session_duration = 3600

  tags = { component = "retained" }
}

data "aws_iam_policy_document" "retained_delivery" {
  statement {
    sid       = "PublishToTheRetainedTopics"
    actions   = ["sns:Publish"]
    resources = values(local.retained_topic_arns)
  }

  # The audit key, through SNS only; its policy repeats the condition (RetainedAlertsPublishThroughSns).
  statement {
    sid       = "UseTheAuditKeyThroughSns"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [for v in values(local.retained_alert_regions) : v.key]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in keys(local.retained_alert_regions) : "sns.${r}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "retained_delivery" {
  name   = "deliver"
  role   = aws_iam_role.retained_delivery.id
  policy = data.aws_iam_policy_document.retained_delivery.json
}

# --- The topics, one per Region -------------------------------------------------------------------------------------

data "aws_iam_policy_document" "retained_topic" {
  for_each = local.retained_topic_arns

  statement {
    sid       = "TheDeliveryRolePublishes"
    actions   = ["sns:Publish"]
    resources = [each.value]

    principals {
      type        = "AWS"
      identifiers = [local.retained_delivery_arn]
    }
  }

  statement {
    sid       = "NobodyElsePublishes"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [each.value]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [local.retained_delivery_arn]
    }
  }

  # BreakGlass holds AdministratorAccess, so the topic guards itself, as the environment's alert topics do.
  statement {
    sid    = "OnlyTheRetainedStackChangesTheTopic"
    effect = "Deny"
    actions = [
      "sns:AddPermission", "sns:DeleteTopic", "sns:PutDataProtectionPolicy", "sns:RemovePermission",
      "sns:SetTopicAttributes",
    ]
    resources = [each.value]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.state_principal_arns
    }
  }
}

resource "aws_sns_topic" "retained_tokyo" {
  name              = "sft-prod-${module.conventions.region_short}-retained-alerts"
  kms_master_key_id = module.audit_key.key_arns["audit"]

  tags = { component = "retained" }
}

resource "aws_sns_topic" "retained_osaka" {
  provider = aws.osaka

  name              = "sft-prod-${module.conventions.region_shorts["ap-northeast-3"]}-retained-alerts"
  kms_master_key_id = module.audit_key_osaka.key_arns["audit"]

  tags = { component = "retained" }
}

resource "aws_sns_topic_policy" "retained_tokyo" {
  arn    = aws_sns_topic.retained_tokyo.arn
  policy = data.aws_iam_policy_document.retained_topic[module.conventions.region].json
}

resource "aws_sns_topic_policy" "retained_osaka" {
  provider = aws.osaka

  arn    = aws_sns_topic.retained_osaka.arn
  policy = data.aws_iam_policy_document.retained_topic["ap-northeast-3"].json
}

resource "aws_sns_topic_subscription" "retained_tokyo" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.retained_tokyo.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_sns_topic_subscription" "retained_osaka" {
  provider = aws.osaka
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.retained_osaka.arn
  protocol  = "email"
  endpoint  = each.value
}

# --- The rules ------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "retained_tokyo" {
  for_each = { for k, v in local.retained_rules : k => v if v.region == module.conventions.region }

  name          = each.value.name
  description   = "${each.value.alert}: ${each.value.summary}"
  event_pattern = jsonencode(each.value.pattern)

  tags = { component = "retained" }
}

resource "aws_cloudwatch_event_rule" "retained_osaka" {
  provider = aws.osaka
  for_each = { for k, v in local.retained_rules : k => v if v.region == "ap-northeast-3" }

  name          = each.value.name
  description   = "${each.value.alert}: ${each.value.summary}"
  event_pattern = jsonencode(each.value.pattern)

  tags = { component = "retained" }
}

locals {
  # Who, what, where and when; never requestParameters or responseElements (as modules/alarms, security-events.tf).
  retained_input_paths = {
    time        = "$.time"
    region      = "$.region"
    event_name  = "$.detail.eventName"
    caller      = "$.detail.userIdentity.arn"
    caller_type = "$.detail.userIdentity.type"
    source_ip   = "$.detail.sourceIPAddress"
    error_code  = "$.detail.errorCode"
    event_id    = "$.detail.eventID"
  }
  retained_input_template = {
    for k, v in local.retained_rules : k => <<-EOT
      {
        "alert": "${v.alert}",
        "severity": "page",
        "summary": "${v.summary}",
        "runbook_url": "${local.retained_runbook}",
        "time": <time>,
        "region": <region>,
        "event_name": <event_name>,
        "caller": <caller>,
        "caller_type": <caller_type>,
        "source_ip": <source_ip>,
        "error_code": <error_code>,
        "cloudtrail_event_id": <event_id>
      }
    EOT
  }
}

resource "aws_cloudwatch_event_target" "retained_tokyo" {
  for_each = aws_cloudwatch_event_rule.retained_tokyo

  rule      = each.value.name
  target_id = "retained-alerts"
  arn       = aws_sns_topic.retained_tokyo.arn
  role_arn  = aws_iam_role.retained_delivery.arn

  input_transformer {
    input_paths    = local.retained_input_paths
    input_template = local.retained_input_template[each.key]
  }

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
}

resource "aws_cloudwatch_event_target" "retained_osaka" {
  provider = aws.osaka
  for_each = aws_cloudwatch_event_rule.retained_osaka

  rule      = each.value.name
  target_id = "retained-alerts"
  arn       = aws_sns_topic.retained_osaka.arn
  role_arn  = aws_iam_role.retained_delivery.arn

  input_transformer {
    input_paths    = local.retained_input_paths
    input_template = local.retained_input_template[each.key]
  }

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
}
