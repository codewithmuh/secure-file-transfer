# The account's observability roles (ADR-0009): one per workload that calls AWS, each reached only through EKS Pod
# Identity by its one service account in monitoring, in any of this environment's clusters, never IRSA. Created by the
# Tokyo stack (create_iam); every Region's stack binds them to its own cluster. Each carries the observability
# boundary, which allows no IAM change and no role assumption (modules/terraform-oidc-roles).
#
# The logs key's policy already names sft-<env>-loki and sft-<env>-tempo through S3 (modules/kms-keys); the platform
# key's names sft-<env>-alertmanager through SNS, for the alert topics (#246).

locals {
  key_arns = [for r in var.regions : "arn:aws:kms:${r}:${var.account_id}:key/*"]

  store_buckets = {
    for k in ["loki", "tempo"] : k => [for r, p in local.regional_prefixes : "arn:aws:s3:::${p}-${k}-${var.account_id}"]
  }

  # The topics Alertmanager publishes to (deploy/observability/charts/prometheus): sft-<env>-<region-short>-<name>.
  alert_topics = flatten([
    for r, p in local.regional_prefixes : [
      for t in ["alerts-page", "alerts-ticket", "heartbeat"] : "arn:aws:sns:${r}:${var.account_id}:${p}-${t}"
    ]
  ])

  store_policy = {
    for k, buckets in local.store_buckets : k => [
      {
        Sid      = "ListItsBuckets"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = buckets
      },
      {
        Sid      = "ReadWriteDeleteItsObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"]
        Resource = [for b in buckets : "${b}/*"]
      },
      {
        Sid       = "LogsKeyThroughS3"
        Effect    = "Allow"
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = { "kms:ResourceAliases" = ["alias/sft/${var.environment}/logs"] }, StringEquals = { "kms:ViaService" = [for r in var.regions : "s3.${r}.amazonaws.com"] } }
      },
    ]
  }

  policies = merge(local.store_policy, {
    alertmanager = [
      {
        Sid      = "PublishToAlertTopics"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = local.alert_topics
      },
      {
        Sid       = "PlatformKeyThroughSns"
        Effect    = "Allow"
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = { "kms:ResourceAliases" = ["alias/sft/${var.environment}/platform"] }, StringEquals = { "kms:ViaService" = [for r in var.regions : "sns.${r}.amazonaws.com"] } }
      },
    ]
    # CloudWatch's read actions take no resource; the Region condition keeps them to this environment's Regions.
    cloudwatch-exporter = [
      {
        Sid       = "ReadMetrics"
        Effect    = "Allow"
        Action    = ["cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics"]
        Resource  = ["*"]
        Condition = { StringEquals = { "aws:RequestedRegion" = var.regions } }
      },
    ]
  })
}

data "aws_iam_policy_document" "trust" {
  for_each = var.create_iam ? local.roles : {}

  statement {
    sid     = "PodIdentity"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/eks-cluster-arn"
      values   = local.cluster_arns
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = [local.namespace]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = [each.value.service_account]
    }
  }
}

resource "aws_iam_role" "this" {
  for_each = var.create_iam ? local.roles : {}

  name                 = "${local.global_prefix}-${each.key}"
  description          = "${each.value.description}, in ${local.global_prefix}, through EKS Pod Identity (${local.namespace})."
  assume_role_policy   = data.aws_iam_policy_document.trust[each.key].json
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy" "this" {
  for_each = var.create_iam ? local.roles : {}

  name   = "workload"
  role   = aws_iam_role.this[each.key].name
  policy = jsonencode({ Version = "2012-10-17", Statement = local.policies[each.key] })
}

resource "aws_eks_pod_identity_association" "this" {
  for_each = local.roles

  cluster_name    = var.cluster_name
  namespace       = local.namespace
  service_account = each.value.service_account
  role_arn        = local.role_arns[each.key]

  tags = {
    component = "observability"
  }

  depends_on = [aws_iam_role.this, aws_iam_role_policy.this]
}
