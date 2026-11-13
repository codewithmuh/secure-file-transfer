# ---------------------------------------------------------------------------------------------------------------------
# Observability (#243): what modules/observability needs in the cluster-bootstrap stacks, in the Regions of
# var.network_regions, and the boundary its roles carry. Deploy role only, like the rest of that layer
# (permissions-cluster-bootstrap.tf): it is planned and applied only on main.
#
# - S3: the buckets sft-<env>-<rs>-{loki,tempo}-<account>, their settings, and emptying them at teardown (logs and
#   traces are derived data, kept 90 and 14 days at most, NFR-19).
# - IAM: the roles sft-<env>-{loki,tempo,alertmanager,cloudwatch-exporter}, by exact ARN, each created only with the
#   observability boundary below, passed only to Pod Identity, and never assumable by this role.
# - The boundary itself: the most any of those roles may ever do. S3 object calls, the logs and platform keys through
#   S3 and SNS, SNS publish and CloudWatch reads, in our Regions; never an IAM change or a role assumption.
#
# The Pod Identity associations are the cluster layer's eks:*PodIdentityAssociation permissions (permissions-cluster.tf).
# The deploy role's thirteenth managed policy, within the raised quota of 20 (infra/README.md, "IAM quotas").
# ---------------------------------------------------------------------------------------------------------------------

locals {
  observability_enabled = local.cluster_enabled && var.github_environment != null

  observability_region_shorts = var.conventions.region_shorts

  observability_bucket_arns = flatten([
    for r in var.network_regions : [
      for store in ["loki", "tempo"] :
      "arn:aws:s3:::${local.cluster_env_prefix}-${local.observability_region_shorts[r]}-${store}-${var.account_id}"
    ]
  ])

  observability_role_arns = [
    for name in ["loki", "tempo", "alertmanager", "cloudwatch-exporter"] :
    "arn:aws:iam::${var.account_id}:role/${local.cluster_env_prefix}-${name}"
  ]

  observability_boundary_name = "${local.cluster_env_prefix}-observability-boundary"
  observability_boundary_arn  = "arn:aws:iam::${var.account_id}:policy${var.iam_path}${local.observability_boundary_name}"
}

data "aws_iam_policy_document" "observability_boundary" {
  count = local.cluster_enabled ? 1 : 0

  statement {
    sid = "ObservabilityServices"
    actions = [
      "s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject", "s3:ListBucket", "s3:PutObject",
      "kms:Decrypt", "kms:GenerateDataKey",
      "sns:Publish",
      "cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid       = "NeverAssumeARole"
    effect    = "Deny"
    actions   = ["sts:AssumeRole"]
    resources = ["*"]
  }

  statement {
    sid       = "NeverChangeIam"
    effect    = "Deny"
    actions   = ["iam:*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "observability_boundary" {
  count = local.cluster_enabled ? 1 : 0

  name        = local.observability_boundary_name
  path        = var.iam_path
  description = "Permissions boundary of the observability roles (#243): telemetry storage, alerts and metric reads only."
  policy      = data.aws_iam_policy_document.observability_boundary[0].json
}

data "aws_iam_policy_document" "observability" {
  count = local.observability_enabled ? 1 : 0

  statement {
    sid = "ReadStores"
    actions = [
      "s3:GetAccelerateConfiguration", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLocation",
      "s3:GetBucketLogging", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketOwnershipControls",
      "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:GetBucketRequestPayment", "s3:GetBucketTagging",
      "s3:GetBucketVersioning", "s3:GetBucketWebsite", "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:ListBucket",
    ]
    resources = local.observability_bucket_arns
  }

  statement {
    sid = "ManageStores"
    actions = [
      "s3:CreateBucket", "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketOwnershipControls",
      "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock", "s3:PutBucketTagging", "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]
    resources = local.observability_bucket_arns
  }

  # Teardown: force_destroy empties the buckets before deleting them.
  statement {
    sid       = "EmptyStoresAtTeardown"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ListBucketVersions"]
    resources = concat(local.observability_bucket_arns, [for b in local.observability_bucket_arns : "${b}/*"])
  }

  statement {
    sid       = "CreateRolesWithBoundary"
    actions   = ["iam:CreateRole", "iam:PutRolePolicy", "iam:PutRolePermissionsBoundary"]
    resources = local.observability_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.observability_boundary_arn]
    }
  }

  # Changes that grant nothing new. The boundary can't be removed: no DeleteRolePermissionsBoundary.
  statement {
    sid = "ReadChangeAndDeleteOwnRoles"
    actions = [
      "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole", "iam:ListRolePolicies", "iam:TagRole", "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:UpdateRoleDescription",
    ]
    resources = local.observability_role_arns
  }

  statement {
    sid       = "PassRolesToPodIdentity"
    actions   = ["iam:PassRole"]
    resources = local.observability_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["pods.eks.amazonaws.com"]
    }
  }

  # It writes these roles' trust, so it could name itself there; an explicit deny wins over any trust policy.
  statement {
    sid       = "NeverAssumeTheRolesItWrites"
    effect    = "Deny"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = local.observability_role_arns
  }
}

resource "aws_iam_policy" "observability" {
  count = local.observability_enabled ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-observability"
  path        = var.iam_path
  description = "Terraform deploy: Loki's and Tempo's buckets and the observability roles (#243)."
  policy      = data.aws_iam_policy_document.observability[0].json
}

resource "aws_iam_role_policy_attachment" "deploy_observability" {
  count = local.observability_enabled ? 1 : 0

  role       = aws_iam_role.deploy[0].name
  policy_arn = aws_iam_policy.observability[0].arn
}
