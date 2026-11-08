# ---------------------------------------------------------------------------------------------------------------------
# Identity layer (#185): what environments/<env>/<region>/identity needs (modules/ses, modules/user-pool,
# modules/app-secrets), in the Regions of var.network_regions. The plan role reads (`sft-<env>-terraform-identity-read`);
# the deploy role's one policy (`-identity`) holds the same reads and also creates, changes and deletes. The DNS
# records go through the environment's DNS roles in the shared account, which the edge layer's permissions already let
# both roles assume; KMS aliases are read through the storage layer's read policy.
#
# - SES: identities, DKIM, MAIL FROM, configuration sets and their event destinations, the identity policy and the
#   configuration set's own suppression setting, all in our Regions; no sending (the notification worker sends).
# - SNS: the ses-events topic only (sft-<env>-<rs>-ses-events), its policy and its subscription.
# - Cognito: the members' pools (sft-<env>-<rs>-members), their domain, client and managed login branding; never a
#   user. Creating a client makes Cognito generate its first secret, which reaches state; the key rotation job
#   replaces it (encryption 6.4).
# - Secrets Manager: creating, tagging, replicating and deleting the sft/<env>/app/* secrets, never a value:
#   PutSecretValue and GetSecretValue are not here (only the key rotation job writes them).
# - WAF: associating the edge's sign-in web ACL with the pool.
#
# This is the deploy role's eleventh managed policy, one over IAM's default quota of 10 per role (infra/README.md,
# "IAM quotas"): the account's quota "Managed policies per role" (L-0DA4ABF3) is raised to 20 before the bootstrap
# apply that adds it. The reads are folded into it rather than attached apart, so the deploy role needs only one more.
# The plan role goes from 4 to 5.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  identity_enabled = local.cluster_enabled

  identity_region_shorts = { "ap-northeast-1" = "apne1", "ap-northeast-3" = "apne3" }
  identity_prefixes      = [for r in var.network_regions : "${local.cluster_env_prefix}-${local.identity_region_shorts[r]}"]

  identity_topics  = [for i, r in var.network_regions : "arn:aws:sns:${r}:${var.account_id}:${local.identity_prefixes[i]}-ses-events"]
  identity_secrets = [for r in var.network_regions : "arn:aws:secretsmanager:${r}:${var.account_id}:secret:${local.cluster_env_prefix_path}/app/*"]
  identity_ses     = [for r in var.network_regions : "arn:aws:ses:${r}:${var.account_id}:*"]
  identity_pools   = [for r in var.network_regions : "arn:aws:cognito-idp:${r}:${var.account_id}:userpool/*"]

  # sft/<env>, the secrets' prefix, from sft-<env>.
  cluster_env_prefix_path = replace(local.cluster_env_prefix, "-", "/")
}

data "aws_iam_policy_document" "identity_read" {
  count = local.identity_enabled ? 1 : 0

  statement {
    sid = "SesRead"
    actions = [
      "ses:GetEmailIdentity", "ses:GetEmailIdentityPolicies", "ses:GetConfigurationSet",
      "ses:GetConfigurationSetEventDestinations", "ses:ListTagsForResource",
    ]
    resources = local.identity_ses
  }

  statement {
    sid       = "SesEventsTopicRead"
    actions   = ["sns:GetTopicAttributes", "sns:GetSubscriptionAttributes", "sns:ListTagsForResource"]
    resources = concat(local.identity_topics, [for t in local.identity_topics : "${t}:*"])
  }

  statement {
    sid = "MemberUserPoolsRead"
    actions = [
      "cognito-idp:DescribeUserPool", "cognito-idp:GetUserPoolMfaConfig", "cognito-idp:DescribeUserPoolClient",
      "cognito-idp:DescribeManagedLoginBranding", "cognito-idp:DescribeManagedLoginBrandingByClient",
      "cognito-idp:ListTagsForResource", "cognito-idp:GetWebACLForResource",
    ]
    resources = local.identity_pools
  }

  # A domain is read by its prefix, which names no pool.
  statement {
    sid       = "UserPoolDomainsRead"
    actions   = ["cognito-idp:DescribeUserPoolDomain"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid       = "SignInWebAclRead"
    actions   = ["wafv2:GetWebACLForResource", "wafv2:GetWebACL"]
    resources = concat(local.identity_pools, [for r in var.network_regions : "arn:aws:wafv2:${r}:${var.account_id}:regional/webacl/*"])
  }

  # The secrets' metadata only, never a value.
  statement {
    sid       = "AppSecretsMetadataRead"
    actions   = ["secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy"]
    resources = local.identity_secrets
  }
}

data "aws_iam_policy_document" "identity" {
  count = local.identity_enabled && var.github_environment != null ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.identity_read[0].json]

  statement {
    sid = "SesIdentitiesAndConfigurationSets"
    actions = [
      "ses:CreateEmailIdentity", "ses:DeleteEmailIdentity", "ses:PutEmailIdentityDkimSigningAttributes",
      "ses:PutEmailIdentityMailFromAttributes", "ses:PutEmailIdentityConfigurationSetAttributes",
      "ses:CreateEmailIdentityPolicy", "ses:UpdateEmailIdentityPolicy", "ses:DeleteEmailIdentityPolicy",
      "ses:CreateConfigurationSet", "ses:DeleteConfigurationSet",
      "ses:PutConfigurationSetDeliveryOptions", "ses:PutConfigurationSetReputationOptions",
      "ses:PutConfigurationSetSendingOptions", "ses:PutConfigurationSetSuppressionOptions",
      "ses:CreateConfigurationSetEventDestination", "ses:UpdateConfigurationSetEventDestination",
      "ses:DeleteConfigurationSetEventDestination", "ses:TagResource", "ses:UntagResource",
    ]
    resources = local.identity_ses
  }

  statement {
    sid       = "SesEventsTopicOnly"
    actions   = ["sns:CreateTopic", "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:Subscribe", "sns:Unsubscribe", "sns:SetSubscriptionAttributes", "sns:TagResource", "sns:UntagResource"]
    resources = concat(local.identity_topics, [for t in local.identity_topics : "${t}:*"])
  }

  statement {
    sid = "MemberUserPoolsNotTheirUsers"
    actions = [
      "cognito-idp:UpdateUserPool", "cognito-idp:DeleteUserPool", "cognito-idp:SetUserPoolMfaConfig",
      "cognito-idp:AddCustomAttributes", "cognito-idp:CreateUserPoolDomain", "cognito-idp:UpdateUserPoolDomain",
      "cognito-idp:DeleteUserPoolDomain", "cognito-idp:CreateUserPoolClient", "cognito-idp:UpdateUserPoolClient",
      "cognito-idp:DeleteUserPoolClient", "cognito-idp:CreateManagedLoginBranding", "cognito-idp:UpdateManagedLoginBranding",
      "cognito-idp:DeleteManagedLoginBranding", "cognito-idp:TagResource", "cognito-idp:UntagResource",
      "cognito-idp:AssociateWebACL", "cognito-idp:DisassociateWebACL",
    ]
    resources = local.identity_pools
  }

  # CreateUserPool names no pool yet.
  statement {
    sid       = "CreatePoolsInOurRegions"
    actions   = ["cognito-idp:CreateUserPool", "cognito-idp:ListUserPools"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid       = "AssociateTheSignInWebAcl"
    actions   = ["wafv2:AssociateWebACL", "wafv2:DisassociateWebACL"]
    resources = concat(local.identity_pools, [for r in var.network_regions : "arn:aws:wafv2:${r}:${var.account_id}:regional/webacl/*"])
  }

  statement {
    sid = "AppSecretsWithoutValues"
    actions = [
      "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret",
      "secretsmanager:TagResource", "secretsmanager:UntagResource",
      "secretsmanager:ReplicateSecretToRegions", "secretsmanager:RemoveRegionsFromReplication",
    ]
    resources = local.identity_secrets
  }
}

resource "aws_iam_policy" "identity_read" {
  count = local.identity_enabled ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-identity-read"
  path        = var.iam_path
  description = "Terraform plan: read SES, the member user pools and the application secrets' metadata (#185)."
  policy      = data.aws_iam_policy_document.identity_read[0].json
}

resource "aws_iam_role_policy_attachment" "plan_identity" {
  count = local.identity_enabled ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.identity_read[0].arn
}

resource "aws_iam_policy" "identity" {
  count = local.identity_enabled && var.github_environment != null ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-identity"
  path        = var.iam_path
  description = "Terraform deploy: SES, the member user pools and the application secrets, without values (#185)."
  policy      = data.aws_iam_policy_document.identity[0].json
}

resource "aws_iam_role_policy_attachment" "deploy_identity" {
  count = local.identity_enabled && var.github_environment != null ? 1 : 0

  role       = aws_iam_role.deploy[0].name
  policy_arn = aws_iam_policy.identity[0].arn
}
