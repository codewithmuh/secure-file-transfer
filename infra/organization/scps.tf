# Service control policies (ADR-0006). They bind every principal in the member accounts, BreakGlass and each account's
# own administrators included, but never the management account. Five policies, grouped by purpose. AWS allows ten per
# target and 10,240 characters each since May 2026 (five and 5,120 before), so the grouping leaves room. The root holds
# FullAWSAccess and SCPs 1 to 4; the prod OU adds SCP 5. Every statement denies: FullAWSAccess, which AWS attaches to
# the root and to each OU and account, stays the only allow.
#
# Principals are matched by role ARN in any member account (an SCP never applies outside the organization):
# - deploy roles: sft-<env>-terraform-deploy under /sft-bootstrap/, and the retained stack's own deploy role,
#   sft-prod-retained-terraform-deploy, which the same pattern matches (ADR-0006, "deploy roles");
# - Admin: Identity Center's role for that permission set, whose name ends in a random suffix;
# - the key-admin role, sft-<env>-keyadmin (ADR-0017);
# - the emergency users of staging and prod, sft-<env>-emergency under /sft-emergency/ (authn-authz 8.4), by exact
#   name: in a Tokyo outage, when Identity Center and so Admin are gone, they administer Osaka's state bucket and
#   tfstate key, which name them (#81). Only those policies name them, so the exemptions below reach nothing else.
# Only Admin may create or change roles under /sft-bootstrap/ and IAM users (SCP 4), so no other principal can take
# one of those names.

locals {
  japan_regions = ["ap-northeast-1", "ap-northeast-3"]

  bootstrap_role_arn_prefix = "arn:aws:iam::*:role${module.conventions.bootstrap_iam_path}"

  deploy_role_arns          = ["${local.bootstrap_role_arn_prefix}sft-*-terraform-deploy"]
  retained_deploy_role_arns = ["${local.bootstrap_role_arn_prefix}sft-prod-retained-terraform-deploy"]
  key_admin_role_arns       = ["${local.bootstrap_role_arn_prefix}sft-*-keyadmin"]
  # Identity Center puts its roles under /aws-reserved/sso.amazonaws.com/<region>/, a path nobody else can use.
  admin_role_arns = ["arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_Admin_*"]
  # The accounts with an Osaka state bucket. The name is the conventions module's emergency_user for each.
  emergency_user_arns = [
    for env in ["staging", "prod"] :
    "arn:aws:iam::*:user${module.conventions.emergency_user.path}sft-${env}-emergency"
  ]

  # --- SCP 1: region guard (NFR-21) ------------------------------------------------------------------------------

  # Global and account-level services, allowed from any Region. Their requests arrive as us-east-1. IAM, Route 53,
  # Budgets and CloudFront are NFR-21's exemptions; the rest exist only globally (ADR-0006): Organizations, account
  # settings, billing and Cost Explorer, Support, Health, and STS's global endpoint, which holds no data.
  # vpce:AllowMultiRegion authorizes the cross-Region S3 endpoint (ADR-0021); the endpoint itself stays guarded below.
  global_actions = [
    "account:*", "aws-portal:*", "billing:*", "budgets:*", "ce:*", "cloudfront:*", "cur:*", "health:*", "iam:*",
    "organizations:*", "route53:*", "sts:*", "support:*", "vpce:AllowMultiRegion",
  ]

  # What CloudFront and Route 53 need in us-east-1 and nowhere else outside Japan (NFR-21): the certificate, the web
  # ACL, CloudWatch metrics and alarms with the SNS topic they notify, the CloudWatch Logs delivery of the web ACL's
  # logs to Tokyo, and the KMS key that signs the zone (DNSSEC).
  us_east_1_actions = ["acm:*", "cloudwatch:*", "kms:*", "logs:*", "sns:*", "wafv2:*"]

  scp_region_guard = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyOutsideJapan"
        Effect    = "Deny"
        NotAction = concat(local.global_actions, local.us_east_1_actions)
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = local.japan_regions } }
      },
      {
        Sid       = "DenyUsEast1ServicesElsewhere"
        Effect    = "Deny"
        Action    = local.us_east_1_actions
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = concat(local.japan_regions, ["us-east-1"]) } }
      },
      {
        # The web ACL's logs pass through us-east-1 to Tokyo; none are stored there (ADR-0008).
        Sid       = "DenyLogGroupsInUsEast1"
        Effect    = "Deny"
        Action    = ["logs:CreateLogGroup"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } }
      },
      {
        # A replica key in another Region would let data be decrypted there (encryption 4.4, rule 4).
        Sid       = "DenyKeyReplicasOutsideOsaka"
        Effect    = "Deny"
        Action    = ["kms:ReplicateKey"]
        Resource  = "*"
        Condition = { StringNotEquals = { "kms:ReplicaRegion" = "ap-northeast-3" } }
      },
      {
        # Cross-Region PrivateLink only between Tokyo and Osaka (ADR-0021).
        Sid      = "DenyEndpointsToOtherRegions"
        Effect   = "Deny"
        Action   = ["ec2:CreateVpcEndpoint"]
        Resource = "*"
        Condition = {
          StringNotEquals = { "ec2:VpceServiceRegion" = local.japan_regions }
          Null            = { "ec2:VpceServiceRegion" = "false" }
        }
      },
    ]
  }

  # --- SCP 2: keys (encryption decision 13, T-61) ----------------------------------------------------------------

  # Admin is exempt because it applies the bootstrap stacks, which create the tfstate keys, and the emergency users
  # because they stand in for Admin on Osaka's tfstate key in a Tokyo outage; the key policies are what keep them to
  # those keys, since no other key policy names them. BreakGlass may still enable a key and cancel a pending
  # deletion, which the key policies allow.
  scp_keys = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OnlyDeployRolesAndAdminDisableOrDeleteKeys"
        Effect   = "Deny"
        Action   = ["kms:DeleteImportedKeyMaterial", "kms:DisableKey", "kms:ScheduleKeyDeletion"]
        Resource = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = concat(local.deploy_role_arns, local.admin_role_arns, local.emergency_user_arns)
          }
        }
      },
      {
        # The key-admin role may only put a key policy back (ADR-0017).
        Sid      = "OnlyDeployRolesAdminAndKeyAdminPutKeyPolicies"
        Effect   = "Deny"
        Action   = ["kms:PutKeyPolicy"]
        Resource = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = concat(
              local.deploy_role_arns, local.admin_role_arns, local.key_admin_role_arns, local.emergency_user_arns,
            )
          }
        }
      },
    ]
  }

  # --- SCP 3: accounts and logging (T-60, T-74, T-75) ------------------------------------------------------------

  apply_role_arns = concat(local.deploy_role_arns, local.admin_role_arns)

  # The Terraform state buckets' own settings (T-73, #81): what would erase, expose or let someone forge state through
  # the bucket rather than its objects. The state bucket policy denies the same actions to everyone but the bootstrap
  # admins (modules/tfstate-backend, DenyBucketSettingsToEveryoneElse); this holds even if that policy is replaced.
  state_bucket_settings_actions = [
    "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketOwnershipControls",
    "s3:PutBucketPublicAccessBlock", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration",
    "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
    "s3:PutInventoryConfiguration",
  ]

  scp_accounts_and_logging = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyLeavingTheOrganization"
        Effect   = "Deny"
        Action   = ["organizations:LeaveOrganization"]
        Resource = "*"
      },
      {
        # Member accounts have no root credentials (centralized root access, main.tf). This also stops one recovered
        # or added later. Sessions from sts:AssumeRoot, run from the management account, carry aws:AssumedRoot.
        Sid      = "DenyRootUserCredentials"
        Effect   = "Deny"
        Action   = ["*"]
        Resource = "*"
        Condition = {
          ArnLike = { "aws:PrincipalArn" = "arn:aws:iam::*:root" }
          Null    = { "aws:AssumedRoot" = "true" }
        }
      },
      {
        # Nothing in the design shares a snapshot, inside or outside the organization (T-60).
        Sid      = "DenySharingSnapshots"
        Effect   = "Deny"
        Action   = ["ec2:ModifySnapshotAttribute", "rds:ModifyDBClusterSnapshotAttribute", "rds:ModifyDBSnapshotAttribute"]
        Resource = "*"
      },
      {
        # Account-wide S3 Block Public Access and EBS default encryption: set by an apply, never turned off by hand.
        Sid       = "OnlyApplyRolesChangeAccountGuards"
        Effect    = "Deny"
        Action    = ["ec2:DisableEbsEncryptionByDefault", "s3:PutAccountPublicAccessBlock"]
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.apply_role_arns } }
      },
      {
        # CloudTrail, Config, GuardDuty (including the filters and IP lists that could hide findings) and EKS
        # control-plane logging, which eks:UpdateClusterConfig sets along with endpoint access (ADR-0006).
        Sid    = "OnlyApplyRolesChangeSecurityServices"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors",
          "cloudtrail:StopLogging", "cloudtrail:UpdateTrail",
          "config:Delete*", "config:DisassociateResourceTypes", "config:PutConfigRule", "config:PutConfigurationRecorder",
          "config:PutDeliveryChannel", "config:PutRetentionConfiguration", "config:PutServiceLinkedConfigurationRecorder",
          "config:Stop*",
          "eks:UpdateClusterConfig",
          "guardduty:CreateFilter", "guardduty:CreateIPSet", "guardduty:CreateTrustedEntitySet", "guardduty:Delete*",
          "guardduty:Disassociate*", "guardduty:Stop*", "guardduty:Update*",
        ]
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.apply_role_arns } }
      },
      {
        # Our alert rules and alarms, all named sft-*, and the EKS control-plane log groups, which hold the Kubernetes
        # audit log that records every exec under break-glass (authn-authz 8.3).
        Sid    = "OnlyApplyRolesChangeAlertsAndAuditLogs"
        Effect = "Deny"
        Action = [
          "cloudwatch:DeleteAlarms", "cloudwatch:DisableAlarmActions", "cloudwatch:PutCompositeAlarm",
          "cloudwatch:PutMetricAlarm",
          "events:DeleteRule", "events:DisableRule", "events:PutRule", "events:PutTargets", "events:RemoveTargets",
          "logs:DeleteLogGroup", "logs:DeleteLogStream", "logs:PutRetentionPolicy",
        ]
        Resource = [
          "arn:aws:cloudwatch:*:*:alarm:sft-*",
          "arn:aws:events:*:*:rule/sft-*",
          "arn:aws:logs:*:*:log-group:/aws/eks/*",
        ]
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.apply_role_arns } }
      },
      {
        # Only Admin, which applies the bootstrap stacks, and the emergency users, which stand in for it in Osaka,
        # change a state bucket; deploy roles never do. The pattern matches each sft-<env>-<region-short>-tfstate-
        # <account-id>, not the retained stack's sft-prod-apne1-retained-tfstate-*, which SCP 5 guards. Assumed-root
        # sessions, the only root left in a member account (DenyRootUserCredentials), pass, so the runbook's way out
        # of a bucket policy that locks the admins out still works.
        Sid      = "OnlyAdminChangesStateBuckets"
        Effect   = "Deny"
        Action   = local.state_bucket_settings_actions
        Resource = ["arn:aws:s3:::sft-*-apne?-tfstate-*"]
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = concat(local.admin_role_arns, local.emergency_user_arns, ["arn:aws:iam::*:root"])
          }
        }
      },
    ]
  }

  # --- SCP 4: IAM (T-71, T-74) -----------------------------------------------------------------------------------

  iam_change_actions = [
    "iam:AttachRolePolicy", "iam:CreateRole", "iam:DeleteRole", "iam:DeleteRolePermissionsBoundary",
    "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary", "iam:PutRolePolicy",
    "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:UpdateRoleDescription",
    "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AddClientIDToOpenIDConnectProvider", "iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider",
    "iam:RemoveClientIDFromOpenIDConnectProvider", "iam:TagOpenIDConnectProvider", "iam:UntagOpenIDConnectProvider",
    "iam:UpdateOpenIDConnectProviderThumbprint",
    "iam:CreateSAMLProvider", "iam:DeleteSAMLProvider", "iam:UpdateSAMLProvider",
  ]

  # What the bootstrap stacks create, which only Admin may change: the roles and any managed policies under
  # /sft-bootstrap/, GitHub's OIDC provider, and the access role Organizations made in each account.
  bootstrap_iam_resources = [
    "${local.bootstrap_role_arn_prefix}*",
    "arn:aws:iam::*:policy${module.conventions.bootstrap_iam_path}*",
    "arn:aws:iam::*:oidc-provider/token.actions.githubusercontent.com",
    "arn:aws:iam::*:role/OrganizationAccountAccessRole",
  ]

  scp_iam = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid         = "OnlyDeployRolesChangeIam"
        Effect      = "Deny"
        Action      = local.iam_change_actions
        NotResource = local.bootstrap_iam_resources
        Condition   = { ArnNotLike = { "aws:PrincipalArn" = local.deploy_role_arns } }
      },
      {
        # So no deploy role can widen its own trust or permissions (T-71).
        Sid       = "OnlyAdminChangesBootstrapIam"
        Effect    = "Deny"
        Action    = local.iam_change_actions
        Resource  = local.bootstrap_iam_resources
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.admin_role_arns } }
      },
      {
        # No long-lived AWS keys anywhere (T-71, T-74), for anyone.
        Sid      = "DenyLongLivedCredentials"
        Effect   = "Deny"
        Action   = ["iam:CreateAccessKey", "iam:CreateServiceSpecificCredential"]
        Resource = "*"
      },
      {
        # People sign in through Identity Center. The only IAM users are the emergency users of authn-authz 8.4, which
        # the state bucket and key policies in Osaka name (#81): nobody but Admin may create one, rename or move a user
        # into its name, set its password or MFA device, or remove it or its policy.
        Sid    = "OnlyAdminManagesIamUsers"
        Effect = "Deny"
        Action = [
          "iam:AddUserToGroup", "iam:AttachUserPolicy", "iam:CreateLoginProfile", "iam:CreateUser", "iam:PutUserPolicy",
          "iam:UpdateLoginProfile", "iam:UpdateUser", "iam:DeleteUser", "iam:DeleteLoginProfile", "iam:DetachUserPolicy",
          "iam:DeleteUserPolicy", "iam:RemoveUserFromGroup", "iam:EnableMFADevice", "iam:DeactivateMFADevice",
          "iam:ResyncMFADevice",
        ]
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = local.admin_role_arns } }
      },
    ]
  }

  # --- SCP 5: the audit archive, prod OU only (encryption 8.4) ---------------------------------------------------

  # The retained stack's buckets: the archive in each Region (sft-prod-<region-short>-audit-archive-<account-id>) and
  # its own state and trail buckets (sft-prod-apne1-retained-<thing>-<account-id>). Admin is exempt because the
  # retained stack's first apply runs with it from local state (ADR-0005); after that, only its deploy role applies it.
  scp_audit_archive = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OnlyTheRetainedStackChangesArchiveGuards"
        Effect = "Deny"
        Action = [
          "s3:DeleteBucketPolicy", "s3:PutBucketObjectLockConfiguration", "s3:PutBucketPolicy",
          "s3:PutBucketPublicAccessBlock", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
          "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
        ]
        Resource = [
          "arn:aws:s3:::sft-prod-apne?-audit-archive-*",
          "arn:aws:s3:::sft-prod-apne?-retained-*",
        ]
        Condition = { ArnNotLike = { "aws:PrincipalArn" = concat(local.retained_deploy_role_arns, local.admin_role_arns) } }
      },
    ]
  }

  scps = {
    region-guard = {
      description = "SCP 1 (ADR-0006, NFR-21): Tokyo and Osaka only, plus global services and what CloudFront needs in us-east-1."
      content     = jsonencode(local.scp_region_guard)
      target      = "root"
    }
    keys = {
      description = "SCP 2 (ADR-0006, decision 13): only deploy roles, Admin and the key-admin role change, disable or delete KMS keys."
      content     = jsonencode(local.scp_keys)
      target      = "root"
    }
    accounts-and-logging = {
      description = "SCP 3 (ADR-0006, T-74, T-75): no leaving, no root user, no shared snapshots; logging and alerts only by apply roles."
      content     = jsonencode(local.scp_accounts_and_logging)
      target      = "root"
    }
    iam = {
      description = "SCP 4 (ADR-0006, T-71): IAM only by deploy roles; /sft-bootstrap/ only by Admin; no access keys."
      content     = jsonencode(local.scp_iam)
      target      = "root"
    }
    audit-archive = {
      description = "SCP 5 (ADR-0006, encryption 8.4): the audit archive's guards only by the retained stack's deploy role."
      content     = jsonencode(local.scp_audit_archive)
      target      = "prod"
    }
  }
}

resource "aws_organizations_policy" "scp" {
  for_each = local.scps

  name        = "${module.conventions.global_name_prefix}-scp-${each.key}"
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value.content

  lifecycle {
    precondition {
      condition     = length(each.value.content) <= 10240
      error_message = "SCP ${each.key} is ${length(each.value.content)} characters; AWS allows 10,240."
    }
  }
}

resource "aws_organizations_policy_attachment" "scp" {
  for_each = local.scps

  policy_id = aws_organizations_policy.scp[each.key].id
  target_id = each.value.target == "root" ? local.root_id : aws_organizations_organizational_unit.this[each.value.target].id
}
