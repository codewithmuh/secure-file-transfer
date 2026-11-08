# IAM Identity Center: the permission sets of authn-authz 8 and ADR-0006, the groups people join, and the group
# assignments. Home Region Tokyo (ADR-0006).
#
# AWS offers no API to enable Identity Center for an organization or to set its MFA rules, so the maintainer does both
# in the console (runbook steps 6 and 7) before identity_center_enabled may be true. MFA is required at every sign-in,
# by security key or passkey only (authn-authz 8.1).
#
# Nobody holds Admin or BreakGlass standing. A BreakGlassApprover assigns either one to a person for at most an hour,
# and the assignment is removed afterwards (authn-authz 8.3, ADR-0006). The break-glass tool, which does that with an
# EventBridge Scheduler removal and the alerts, comes with FR-35 (M6); until then the runbook gives the CLI commands.
#
# Permission set names are load-bearing: bucket and key policies match Identity Center's roles by name, for example
# *AWSReservedSSO_Admin_* and *AWSReservedSSO_BreakGlass_* (modules/conventions). Don't rename them, and don't create a
# permission set whose name starts with one of these followed by an underscore.

data "aws_ssoadmin_instances" "this" {
  count = var.identity_center_enabled ? 1 : 0
}

locals {
  sso_instance_arn  = var.identity_center_enabled ? one(data.aws_ssoadmin_instances.this[0].arns) : null
  identity_store_id = var.identity_center_enabled ? one(data.aws_ssoadmin_instances.this[0].identity_store_ids) : null

  member_account_names = keys(local.member_accounts)

  # Session lengths: one hour for everything that can change or read protected data (authn-authz 8.3); longer for
  # the read-only and runbook sets, which re-authenticate with the security key when the portal session ends.
  permission_sets = {
    Admin = {
      description      = "Bootstrap and organization applies only (ADR-0005, ADR-0006). Never standing: assigned for at most one hour."
      session_duration = "PT1H"
      managed_policies = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }
    BreakGlass = {
      description      = "Emergencies only (authn-authz 8.3). Never standing: assigned for at most one hour. SCPs and key policies bind it."
      session_duration = "PT1H"
      managed_policies = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }
    BreakGlassApprover = {
      description      = "Assigns BreakGlass or Admin to another operator for one hour (authn-authz 8.3). Management account only."
      session_duration = "PT1H"
      managed_policies = []
    }
    ReadOnly = {
      description      = "Dashboards, logs, alarms and configuration; no file objects, secrets, decryption or database (authn-authz 8.1)."
      session_duration = "PT4H"
      managed_policies = ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess", "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"]
    }
    Operator = {
      description      = "ReadOnly plus the runbooks: SSO providers in the user pools and the failover steps (authn-authz 8.1)."
      session_duration = "PT2H"
      managed_policies = ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess", "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"]
    }
    AuditReader = {
      description      = "Reads the audit archives and the log archive for an investigation (encryption 8.4)."
      session_duration = "PT1H"
      managed_policies = []
    }
  }

  # Inline policies, for the sets that have one.
  inline_policies = var.identity_center_enabled ? {
    BreakGlassApprover = data.aws_iam_policy_document.break_glass_approver[0].json
    ReadOnly           = data.aws_iam_policy_document.read_only.json
    Operator           = data.aws_iam_policy_document.operator.json
    AuditReader        = data.aws_iam_policy_document.audit_reader.json
  } : {}

  managed_policy_attachments = var.identity_center_enabled ? {
    for pair in flatten([
      for set, config in local.permission_sets : [
        for arn in config.managed_policies : { set = set, arn = arn }
      ]
    ]) : "${pair.set}/${basename(pair.arn)}" => pair
  } : {}

  # Groups and where each is assigned. Admin and BreakGlass have no group: see the header.
  groups = {
    readonly = {
      display_name   = "sft-readonly"
      description    = "ReadOnly in every member account."
      permission_set = "ReadOnly"
      accounts       = local.member_account_names
    }
    operators = {
      display_name   = "sft-operators"
      description    = "Operator in dev, staging and prod."
      permission_set = "Operator"
      accounts       = ["dev", "staging", "prod"]
    }
    breakglass_approvers = {
      display_name   = "sft-breakglass-approvers"
      description    = "BreakGlassApprover in the management account, where Identity Center lives."
      permission_set = "BreakGlassApprover"
      accounts       = ["management"]
    }
    audit_readers = {
      display_name   = "sft-audit-readers"
      description    = "AuditReader in every member account: the archives are in each environment, the log archive in shared."
      permission_set = "AuditReader"
      accounts       = local.member_account_names
    }
  }

  group_assignments = var.identity_center_enabled ? {
    for pair in flatten([
      for group, config in local.groups : [
        for account in config.accounts : { group = group, account = account, permission_set = config.permission_set }
      ]
    ]) : "${pair.group}/${pair.account}" => pair
  } : {}

  group_memberships = var.identity_center_enabled ? {
    for pair in flatten([
      for group, users in var.identity_center_group_members : [for user in users : { group = group, user = user }]
    ]) : "${pair.group}/${pair.user}" => pair
  } : {}
}

# --- Permission sets ---------------------------------------------------------------------------------------------

resource "aws_ssoadmin_permission_set" "this" {
  for_each = var.identity_center_enabled ? local.permission_sets : {}

  name             = each.key
  description      = each.value.description
  instance_arn     = local.sso_instance_arn
  session_duration = each.value.session_duration

  lifecycle {
    precondition {
      condition     = length(data.aws_ssoadmin_instances.this[0].arns) == 1
      error_message = "No IAM Identity Center instance in ap-northeast-1. Enable it for the organization in Tokyo first (docs/runbooks/organization-and-bootstrap.md, step 6)."
    }
  }
}

resource "aws_ssoadmin_managed_policy_attachment" "this" {
  for_each = local.managed_policy_attachments

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.set].arn
  managed_policy_arn = each.value.arn
}

resource "aws_ssoadmin_permission_set_inline_policy" "this" {
  for_each = local.inline_policies

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = each.value
}

# BreakGlassApprover creates and removes assignments of BreakGlass and Admin, and reads who is who. IAM can't tell
# whether the person assigned is someone else; self-approval raises its own alert (authn-authz 8.3, R-08). It can't
# change permission sets, groups or anything else in this account.
data "aws_iam_policy_document" "break_glass_approver" {
  count = var.identity_center_enabled ? 1 : 0

  statement {
    sid     = "AssignBreakGlassAndAdmin"
    actions = ["sso:CreateAccountAssignment", "sso:DeleteAccountAssignment"]
    resources = [
      local.sso_instance_arn,
      aws_ssoadmin_permission_set.this["BreakGlass"].arn,
      aws_ssoadmin_permission_set.this["Admin"].arn,
      "arn:aws:sso:::account/*",
    ]
  }

  statement {
    sid = "ReadAssignmentsAndPeople"
    actions = [
      "identitystore:DescribeUser", "identitystore:GetUserId", "identitystore:ListGroupMembershipsForMember",
      "identitystore:ListUsers",
      "organizations:DescribeOrganization", "organizations:ListAccounts",
      "sso:DescribeAccountAssignmentCreationStatus", "sso:DescribeAccountAssignmentDeletionStatus",
      "sso:DescribePermissionSet", "sso:ListAccountAssignments", "sso:ListAccountAssignmentsForPrincipal",
      "sso:ListInstances", "sso:ListPermissionSets",
    ]
    resources = ["*"]
  }
}

# Reaching the cluster API and Grafana by Systems Manager port forwarding (authn-authz 8.1) needs the session
# document and the system nodes, which come with the cluster layer; that issue adds the ssm statements here.
data "aws_iam_policy_document" "read_only" {
  statement {
    sid       = "FindTheClusters"
    actions   = ["eks:DescribeCluster", "eks:ListClusters"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "operator" {
  source_policy_documents = [data.aws_iam_policy_document.read_only.json]

  # Tenants' SSO connections live in both user pools (authn-authz 2.4, 2.6).
  statement {
    sid = "ManageSsoProvidersInTheUserPools"
    actions = [
      "cognito-idp:CreateIdentityProvider", "cognito-idp:DeleteIdentityProvider",
      "cognito-idp:DescribeIdentityProvider", "cognito-idp:ListIdentityProviders",
      "cognito-idp:UpdateIdentityProvider",
      # The CLI enables a tenant's provider on the app client (#231); the client's other settings it copies back.
      "cognito-idp:DescribeUserPoolClient", "cognito-idp:UpdateUserPoolClient",
    ]
    resources = ["arn:aws:cognito-idp:*:*:userpool/*"]
  }

  # The AWS steps of the failover runbooks are added with those runbooks (M7, #42).
}

# Bucket and key policies decide which archives a reader reaches; this only lets the role ask. Names: the audit
# archive is sft-<env>-<region-short>-audit-archive-<account-id> (in prod, in the retained stack), the organization's
# log archive sft-shared-apne1-log-archive-<account-id>.
data "aws_iam_policy_document" "audit_reader" {
  statement {
    sid       = "FindTheBuckets"
    actions   = ["s3:GetBucketLocation", "s3:ListAllMyBuckets"]
    resources = ["*"]
  }

  statement {
    sid     = "ReadTheArchives"
    actions = ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions"]
    resources = [
      "arn:aws:s3:::sft-*-audit-archive-*",
      "arn:aws:s3:::sft-*-audit-archive-*/*",
      "arn:aws:s3:::sft-shared-*-log-archive-*",
      "arn:aws:s3:::sft-shared-*-log-archive-*/*",
    ]
  }

  statement {
    sid       = "DecryptThroughS3"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:*:*:key/*"]

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3.*.amazonaws.com"]
    }
  }
}

# --- Groups and assignments --------------------------------------------------------------------------------------

resource "aws_identitystore_group" "this" {
  for_each = var.identity_center_enabled ? local.groups : {}

  identity_store_id = local.identity_store_id
  display_name      = each.value.display_name
  description       = each.value.description
}

# People are created in the console, where Identity Center sends the invitation and they register their security key
# (runbook step 7). Terraform only puts them in groups, by user name.
data "aws_identitystore_user" "member" {
  for_each = toset([for pair in values(local.group_memberships) : pair.user])

  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "UserName"
      attribute_value = each.key
    }
  }
}

resource "aws_identitystore_group_membership" "this" {
  for_each = local.group_memberships

  identity_store_id = local.identity_store_id
  group_id          = aws_identitystore_group.this[each.value.group].group_id
  member_id         = data.aws_identitystore_user.member[each.value.user].user_id
}

resource "aws_ssoadmin_account_assignment" "group" {
  for_each = local.group_assignments

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn
  principal_type     = "GROUP"
  principal_id       = aws_identitystore_group.this[each.value.group].group_id
  target_type        = "AWS_ACCOUNT"
  target_id          = local.account_ids[each.value.account]

  # The policies must be in the permission set before it is provisioned into an account.
  depends_on = [aws_ssoadmin_managed_policy_attachment.this, aws_ssoadmin_permission_set_inline_policy.this]
}
