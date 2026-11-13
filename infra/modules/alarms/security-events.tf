# Security alerts from AWS events, not metrics (#256; encryption 4.4 rule 7, authn-authz 8.3 and 8.4; threat model
# T-61, T-64, T-74, T-75): EventBridge rules on CloudTrail's events in this Region, each into the Region's page topic
# through the environment's delivery role, sft-<env>-events-delivery (modules/events-delivery-role, encryption 4.4).
# They need no metric and no cluster, so they page when the cluster is gone, and nothing silences them: Alertmanager's
# drill inhibition never sees them (drill-in-progress.md). CloudTrail delivers management events to EventBridge
# through the organization trail (ADR-0006), with up to a few minutes' delay.
#
# | Rule                             | Fires on                                                                           |
# |----------------------------------|------------------------------------------------------------------------------------|
# | <rs>-kms-key-changed             | A key's policy, state, rotation, grants or replicas changed by anyone but a deploy |
# |                                  | role, or any refused attempt (rule 7)                                              |
# | <rs>-kms-key-destroyed (prod)    | A deploy role disabling a key, its rotation, or scheduling its deletion (rule 7)   |
# | <rs>-key-admin-used              | Any assumption of sft-<env>-keyadmin, and every call it makes (rule 6 and 7)       |
# | <rs>-human-sign-in               | Root, the emergency user, Admin and BreakGlass signing in or acting (8.3, 8.4)     |
# | <rs>-security-service-off        | CloudTrail, GuardDuty or Config changed by anyone but a deploy role, or any refused|
# |                                  | attempt (T-75)                                                                     |
# | <rs>-alerting-or-endpoint-changed| Our sft-* rules deleted, disabled or emptied by anyone but a deploy role, any      |
# |                                  | refused attempt, or the cluster endpoint made public (T-75, ADR-0021)              |
#
# Root and IAM user sign-ins, and calls to STS's global endpoint, record their events in us-east-1. A rule there,
# sft-<env>-<rs>-global-events, forwards exactly those to this Region's default event bus, where the rules above see
# them. Tokyo's stack makes it; Osaka's makes its own once out of the pilot light (pilot_light = false), so a failover
# keeps them. Until then Osaka's rules ignore forwarded events, so nothing pages twice.
#
# The input transformers carry who, what, where and when from each event, never requestParameters or
# responseElements, which can hold a policy, a session's access key ID or a token. Every rule names its runbook.

locals {
  security_runbook = "https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks"

  # The apply roles, which change keys and security services as part of an apply: the environment's deploy role and,
  # in prod, the retained stack's (encryption 8.4).
  deploy_role_arns = concat(
    [var.deploy_role_arn],
    var.environment == "prod" ? ["arn:aws:iam::${var.account_id}:role${var.conventions.bootstrap_iam_path}sft-prod-retained-terraform-deploy"] : [],
  )

  key_admin_role_arn = var.conventions.bootstrap_role_arns.key_admin
  emergency_user_arn = var.conventions.emergency_user.arn

  # Identity Center's permission set roles: their IAM ARNs, which AssumeRoleWithSAML names, and their sessions'
  # ARNs, which sign-ins and calls carry.
  human_role_arns = [var.conventions.sso_role_arn_patterns.admin, var.conventions.sso_role_arn_patterns.break_glass]
  human_session_arns = [
    for set in ["Admin", "BreakGlass"] : "arn:aws:sts::${var.account_id}:assumed-role/AWSReservedSSO_${set}_*"
  ]

  # Who changed it, and whether it was refused: anyone but an apply role, or any refused attempt.
  not_an_apply_role = [
    { userIdentity = { sessionContext = { sessionIssuer = { arn = [{ "anything-but" = local.deploy_role_arns }] } } } },
    { userIdentity = { type = [{ "anything-but" = ["AssumedRole"] }] } },
    { errorCode = [{ exists = true }] },
  ]

  # Tokyo always, and Osaka once out of the pilot light, receive the events us-east-1 forwards; before that Osaka's
  # rules look at Osaka's own events only.
  receives_global_events = var.region == "ap-northeast-1" || !var.pilot_light
  this_region_only       = { for k, v in { region = [var.region] } : k => v if !local.receives_global_events }

  kms_change_events = [
    "CancelKeyDeletion", "DeleteImportedKeyMaterial", "DisableKey", "DisableKeyRotation", "ImportKeyMaterial",
    "PutKeyPolicy", "ReplicateKey", "RevokeGrant", "ScheduleKeyDeletion", "UpdatePrimaryRegion",
  ]
  kms_destroy_events = ["DisableKey", "DisableKeyRotation", "ScheduleKeyDeletion"]

  security_service_events = {
    "cloudtrail.amazonaws.com" = ["DeleteTrail", "PutEventSelectors", "PutInsightSelectors", "StopLogging", "UpdateTrail"]
    "guardduty.amazonaws.com" = [
      "DeleteDetector", "DeleteMalwareProtectionPlan", "DisassociateFromAdministratorAccount",
      "DisassociateFromMasterAccount", "UpdateDetector", "UpdateMalwareProtectionPlan",
    ]
    "config.amazonaws.com" = [
      "DeleteConfigRule", "DeleteConfigurationRecorder", "DeleteDeliveryChannel", "PutConfigurationRecorder",
      "StopConfigurationRecorder",
    ]
  }

  security_rules = merge(
    {
      "kms-key-changed" = {
        alert       = "KmsKeyChanged"
        runbook     = "kms-key-change"
        summary     = "A KMS key's policy, state, rotation, grants or replicas were changed outside an apply, or someone tried (encryption 4.4 rule 7, T-61)."
        all_events  = false
        description = "A KMS key change by anyone but a deploy role, or any refused attempt (encryption 4.4, T-61): pages."
        pattern = merge(local.this_region_only, {
          source        = ["aws.kms"]
          "detail-type" = ["AWS API Call via CloudTrail"]
          detail = {
            eventSource = ["kms.amazonaws.com"]
            eventName   = local.kms_change_events
            "$or"       = local.not_an_apply_role
          }
        })
      }
      "key-admin-used" = {
        alert       = "KeyAdminRoleUsed"
        runbook     = "key-admin-role"
        summary     = "Someone assumed, or tried to assume, the key-admin role, or it made a call (encryption 4.4 rules 6 and 7)."
        all_events  = true
        description = "Any assumption of ${local.key_admin_role_arn} and every call it makes, reads included (encryption 4.4): pages."
        pattern = merge(local.this_region_only, {
          "detail-type" = ["AWS API Call via CloudTrail"]
          detail = {
            "$or" = [
              { eventSource = ["sts.amazonaws.com"], requestParameters = { roleArn = [local.key_admin_role_arn] } },
              { userIdentity = { sessionContext = { sessionIssuer = { arn = [local.key_admin_role_arn] } } } },
            ]
          }
        })
      }
      "human-sign-in" = {
        alert       = "PrivilegedSignIn"
        runbook     = "privileged-sign-in"
        summary     = "The root user, the emergency user, Admin or BreakGlass signed in or acted in this account (authn-authz 8.3, 8.4; T-64, T-74)."
        all_events  = true
        description = "Sign-ins and calls by root, the emergency user, Admin and BreakGlass (authn-authz 8.3, 8.4): pages."
        pattern = merge(local.this_region_only, {
          "$or" = [
            {
              source        = ["aws.signin"]
              "detail-type" = ["AWS Console Sign In via CloudTrail"]
              detail = {
                "$or" = [
                  { userIdentity = { type = ["Root"] } },
                  { userIdentity = { arn = [local.emergency_user_arn] } },
                  { userIdentity = { arn = [for a in local.human_session_arns : { wildcard = a }] } },
                ]
              }
            },
            {
              "detail-type" = ["AWS API Call via CloudTrail"]
              detail = {
                "$or" = [
                  {
                    eventSource       = ["sts.amazonaws.com"]
                    eventName         = ["AssumeRoleWithSAML"]
                    requestParameters = { roleArn = [for a in local.human_role_arns : { wildcard = a }] }
                  },
                  { userIdentity = { type = ["Root"] } },
                  { userIdentity = { arn = [local.emergency_user_arn] } },
                ]
              }
            },
          ]
        })
      }
      "security-service-off" = {
        alert       = "SecurityServiceChanged"
        runbook     = "security-service-off"
        summary     = "CloudTrail, GuardDuty or Config was turned off or changed outside an apply, or someone tried (T-75)."
        all_events  = false
        description = "CloudTrail, GuardDuty and Config changes outside an apply, and any refused attempt (T-75): pages."
        pattern = merge(local.this_region_only, {
          source        = ["aws.cloudtrail", "aws.guardduty", "aws.config"]
          "detail-type" = ["AWS API Call via CloudTrail"]
          detail = {
            eventSource = keys(local.security_service_events)
            eventName   = sort(flatten(values(local.security_service_events)))
            "$or"       = local.not_an_apply_role
          }
        })
      }
      # The alert rules themselves, and the cluster's API endpoint. A separate rule only because one pattern holds at
      # most 4,096 characters.
      "alerting-or-endpoint-changed" = {
        alert       = "SecurityServiceChanged"
        runbook     = "security-service-off"
        summary     = "An sft alert rule was deleted, disabled or emptied outside an apply, someone tried, or the cluster's API endpoint was made public (T-75, ADR-0021)."
        all_events  = false
        description = "sft-* rule changes outside an apply, any refused attempt, and a public cluster endpoint (T-75, ADR-0021): pages."
        pattern = merge(local.this_region_only, {
          "detail-type" = ["AWS API Call via CloudTrail"]
          detail = {
            "$or" = concat(
              # By name: AWS services manage rules of their own, which aren't ours.
              flatten([
                for parameter, events in { name = ["DeleteRule", "DisableRule"], rule = ["RemoveTargets"] } : [
                  for who in local.not_an_apply_role : merge({
                    eventSource       = ["events.amazonaws.com"]
                    eventName         = events
                    requestParameters = { (parameter) = [{ prefix = "sft-${var.environment}-" }] }
                  }, who)
                ]
              ]),
              # A public API endpoint, by anyone: the deploy role can't make one (eks:endpointPublicAccess).
              [{
                eventSource       = ["eks.amazonaws.com"]
                eventName         = ["UpdateClusterConfig"]
                requestParameters = { resourcesVpcConfig = { endpointPublicAccess = [true] } }
              }],
            )
          }
        })
      }
    },
    # In prod a deploy role disabling or deleting a key pages too; the prod teardown acknowledges it in its runbook. In
    # dev and staging those calls by the deploy role are the teardown, and are only logged (rule 7).
    {
      for name, rule in {
        "kms-key-destroyed" = {
          alert       = "KmsKeyDisabledOrDeleted"
          runbook     = "kms-key-change"
          summary     = "A deploy role disabled a prod KMS key or its rotation, or scheduled its deletion (encryption 4.4 rule 7, 8.3)."
          all_events  = false
          description = "A prod key disabled, its rotation turned off or its deletion scheduled by a deploy role (encryption 4.4, 8.3): pages."
          pattern = merge(local.this_region_only, {
            source        = ["aws.kms"]
            "detail-type" = ["AWS API Call via CloudTrail"]
            detail = {
              eventSource  = ["kms.amazonaws.com"]
              eventName    = local.kms_destroy_events
              errorCode    = [{ exists = false }]
              userIdentity = { sessionContext = { sessionIssuer = { arn = local.deploy_role_arns } } }
            }
          })
        }
      } : name => rule if var.environment == "prod"
    },
  )
}

resource "aws_cloudwatch_event_rule" "security" {
  for_each = local.security_rules

  name          = "${var.name_prefix}-${each.key}"
  description   = each.value.description
  event_pattern = jsonencode(each.value.pattern)

  # Reads too (GetKeyPolicy by the key-admin role, anything root or the emergency user does): EventBridge sees
  # CloudTrail's read-only management events only when a rule asks for them.
  state = each.value.all_events ? "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" : "ENABLED"

  tags = { component = "alarms" }
}

resource "aws_cloudwatch_event_target" "security" {
  for_each = local.security_rules

  rule      = aws_cloudwatch_event_rule.security[each.key].name
  target_id = "alerts-page"
  arn       = aws_sns_topic.this["alerts-page"].arn
  role_arn  = local.events_delivery_role_arn

  # Who, what, where and when. Never requestParameters or responseElements: a key policy, a session's access key ID
  # or a token can be in them. A path an event lacks (a root sign-in has no session issuer) arrives empty.
  input_transformer {
    input_paths = {
      time         = "$.time"
      region       = "$.region"
      account      = "$.account"
      event_source = "$.detail.eventSource"
      event_name   = "$.detail.eventName"
      caller       = "$.detail.userIdentity.arn"
      caller_type  = "$.detail.userIdentity.type"
      source_ip    = "$.detail.sourceIPAddress"
      error_code   = "$.detail.errorCode"
      event_id     = "$.detail.eventID"
    }
    input_template = <<-EOT
      {
        "alert": "${each.value.alert}",
        "severity": "page",
        "summary": "${each.value.summary}",
        "runbook_url": "${local.security_runbook}/${each.value.runbook}.md",
        "time": <time>,
        "region": <region>,
        "account": <account>,
        "event_source": <event_source>,
        "event_name": <event_name>,
        "caller": <caller>,
        "caller_type": <caller_type>,
        "source_ip": <source_ip>,
        "error_code": <error_code>,
        "cloudtrail_event_id": <event_id>
      }
    EOT
  }

  # A day of retries, like the environment's other rules: a page delivered late is better than none.
  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
}

# --- us-east-1: forward the global events -------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "global_events" {
  provider = aws.us_east_1
  count    = local.receives_global_events ? 1 : 0

  name        = "${var.name_prefix}-global-events"
  description = "Forwards root, emergency user, Identity Center and key-admin sign-in and STS events to ${var.region}'s security alerts (#256)."
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"

  event_pattern = jsonencode({
    "$or" = [
      { source = ["aws.signin"] },
      {
        source        = ["aws.sts"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          requestParameters = {
            roleArn = concat(
              [local.key_admin_role_arn, "arn:aws:iam::${var.account_id}:role/sft-${var.environment}-break-glass-db"],
              [for a in local.human_role_arns : { wildcard = a }],
            )
          }
        }
      },
      { "detail-type" = ["AWS API Call via CloudTrail"], detail = { userIdentity = { type = ["Root"] } } },
      { "detail-type" = ["AWS API Call via CloudTrail"], detail = { userIdentity = { arn = [local.emergency_user_arn] } } },
    ]
  })

  tags = { component = "alarms", region = "us-east-1" }
}

resource "aws_cloudwatch_event_target" "global_events" {
  provider = aws.us_east_1
  count    = local.receives_global_events ? 1 : 0

  rule      = aws_cloudwatch_event_rule.global_events[0].name
  target_id = "${replace(var.region, "-", "")}-default-bus"
  arn       = "arn:aws:events:${var.region}:${var.account_id}:event-bus/default"
  role_arn  = local.events_delivery_role_arn

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
}
