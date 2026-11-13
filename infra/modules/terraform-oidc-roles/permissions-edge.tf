# ---------------------------------------------------------------------------------------------------------------------
# Edge layer (#105): what the edge stacks (modules/edge, modules/web-cdn) need. Every Region with a network has an
# edge, so the layer follows var.network_regions, plus us-east-1 for CloudFront's certificate, web ACL and log
# delivery (the region guard's exceptions, ADR-0006). The plan role reads; the deploy role also creates, changes and
# deletes. The edge's security group and its rule on main_nodes use the network layer's EC2 permissions, which these
# don't repeat.
#
# Managed policies under /sft-bootstrap/, not inline ones, so the layers together stay inside IAM's limits (inline
# policies share 10,240 characters per role); SCP 4 already gives only Admin the right to change them.
#
# The records in the shared zone are written through the environment's DNS roles there, which the roles here may
# assume: the plan role the read role, the deploy role the write role (ADR-0021).
# ---------------------------------------------------------------------------------------------------------------------

locals {
  edge_enabled = local.network_enabled

  # The environment, from the plan role's name, sft-<env>-terraform-plan (conventions module).
  edge_environment = one(regex("^sft-([a-z]+)-terraform-plan$", var.plan_role_name))

  edge_regions         = concat(var.network_regions, ["us-east-1"])
  edge_region_shorts   = [for region in var.network_regions : var.conventions.region_shorts[region]]
  edge_dns_role_prefix = var.shared_account_id == null ? null : "arn:aws:iam::${var.shared_account_id}:role/sft-shared/sft-shared-dns-${local.edge_environment}"

  # The edge's buckets: the WAF and CloudFront logs, the load balancer's access logs and the web bundle.
  edge_bucket_arns = flatten([
    for short in local.edge_region_shorts : [
      "arn:aws:s3:::aws-waf-logs-sft-${local.edge_environment}-${short}-${var.account_id}",
      "arn:aws:s3:::sft-${local.edge_environment}-${short}-lb-logs-${var.account_id}",
      "arn:aws:s3:::sft-${local.edge_environment}-${short}-web-${var.account_id}",
    ]
  ])

  edge_elb_arns = [for region in var.network_regions : "arn:aws:elasticloadbalancing:${region}:${var.account_id}:*"]

  # The web app's release role (modules/web-release, #283), from the edge layer's list in conventions; Tokyo's edge
  # stack makes it.
  edge_role_arns = [
    for name in lookup(var.conventions.workload_roles, "edge", []) : "arn:aws:iam::${var.account_id}:role/${var.conventions.workload_role_names[name]}"
  ]
}

data "aws_iam_policy_document" "edge_read" {
  count = local.edge_enabled ? 1 : 0

  statement {
    sid = "EdgeDescribe"
    actions = [
      "acm:DescribeCertificate",
      "acm:ListTagsForCertificate",
      "elasticloadbalancing:Describe*",
      "kms:DescribeKey",
      "kms:ListAliases",
      "logs:DescribeDeliveries",
      "logs:DescribeDeliveryDestinations",
      "logs:DescribeDeliverySources",
      "logs:GetDelivery",
      "logs:GetDeliveryDestination",
      "logs:GetDeliveryDestinationPolicy",
      "logs:GetDeliverySource",
      "logs:ListTagsForResource",
      "wafv2:GetIPSet",
      "wafv2:GetLoggingConfiguration",
      "wafv2:GetWebACL",
      "wafv2:GetWebACLForResource",
      "wafv2:ListResourcesForWebACL",
      "wafv2:ListTagsForResource",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = local.edge_regions
    }
  }

  # CloudFront and Route 53 health checks are global.
  statement {
    sid = "EdgeGlobalRead"
    actions = [
      "cloudfront:DescribeFunction",
      "cloudfront:GetCachePolicy",
      "cloudfront:GetDistribution",
      "cloudfront:GetFunction",
      "cloudfront:GetOriginAccessControl",
      "cloudfront:GetResponseHeadersPolicy",
      "cloudfront:ListCachePolicies",
      "cloudfront:ListTagsForResource",
      "route53:GetHealthCheck",
      "route53:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid = "EdgeBucketsRead"
    actions = [
      "s3:GetAccelerateConfiguration",
      "s3:GetBucket*",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
    ]
    resources = local.edge_bucket_arns
  }

  statement {
    sid       = "WebReleaseRoleRead"
    actions   = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"]
    resources = local.edge_role_arns
  }

  dynamic "statement" {
    for_each = local.edge_dns_role_prefix == null ? [] : [1]

    content {
      sid       = "ReadTheSharedZone"
      actions   = ["sts:AssumeRole"]
      resources = ["${local.edge_dns_role_prefix}-plan"]
    }
  }
}

data "aws_iam_policy_document" "edge_write" {
  count = local.edge_enabled ? 1 : 0

  statement {
    sid = "EdgeRegionalWrite"
    actions = [
      "acm:AddTagsToCertificate",
      "acm:DeleteCertificate",
      "acm:RemoveTagsFromCertificate",
      "acm:RequestCertificate",
      "acm:UpdateCertificateOptions",
      "logs:CreateDelivery",
      "logs:CreateLogDelivery",
      "logs:DeleteDelivery",
      "logs:DeleteDeliveryDestination",
      "logs:DeleteDeliverySource",
      "logs:DeleteLogDelivery",
      "logs:PutDeliveryDestination",
      "logs:PutDeliverySource",
      "logs:TagResource",
      "logs:UntagResource",
      "logs:UpdateDeliveryConfiguration",
      "wafv2:AssociateWebACL",
      "wafv2:CreateIPSet",
      "wafv2:CreateWebACL",
      "wafv2:DeleteIPSet",
      "wafv2:DeleteLoggingConfiguration",
      "wafv2:DeleteWebACL",
      "wafv2:DisassociateWebACL",
      "wafv2:PutLoggingConfiguration",
      "wafv2:TagResource",
      "wafv2:UntagResource",
      "wafv2:UpdateIPSet",
      "wafv2:UpdateWebACL",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = local.edge_regions
    }
  }

  statement {
    sid = "LoadBalancerWrite"
    actions = [
      "elasticloadbalancing:AddListenerCertificates",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyListenerAttributes",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:ModifyRule",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:RemoveListenerCertificates",
      "elasticloadbalancing:RemoveTags",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:SetWebAcl",
    ]
    resources = local.edge_elb_arns
  }

  # Deletes only what Terraform made, never what the load balancer controller makes.
  statement {
    sid = "LoadBalancerDeleteOwn"
    actions = [
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteRule",
      "elasticloadbalancing:DeleteTargetGroup",
    ]
    resources = local.edge_elb_arns

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/managed-by"
      values   = ["terraform"]
    }
  }

  statement {
    sid = "EdgeGlobalWrite"
    actions = [
      "cloudfront:AllowVendedLogDeliveryForResource",
      "cloudfront:CreateDistribution",
      "cloudfront:CreateFunction",
      "cloudfront:CreateOriginAccessControl",
      "cloudfront:CreateResponseHeadersPolicy",
      "cloudfront:DeleteDistribution",
      "cloudfront:DeleteFunction",
      "cloudfront:DeleteOriginAccessControl",
      "cloudfront:DeleteResponseHeadersPolicy",
      "cloudfront:PublishFunction",
      "cloudfront:TagResource",
      "cloudfront:UntagResource",
      "cloudfront:UpdateDistribution",
      "cloudfront:UpdateFunction",
      "cloudfront:UpdateOriginAccessControl",
      "cloudfront:UpdateResponseHeadersPolicy",
    ]
    resources = ["arn:aws:cloudfront::${var.account_id}:*"]
  }

  statement {
    sid = "HealthChecks"
    actions = [
      "route53:ChangeTagsForResource",
      "route53:CreateHealthCheck",
      "route53:DeleteHealthCheck",
      "route53:UpdateHealthCheck",
    ]
    resources = ["*"]
  }

  # The edge's buckets only. A teardown empties them (force_destroy).
  statement {
    sid = "EdgeBucketsWrite"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:ListBucketVersions",
      "s3:PutBucket*",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]
    resources = concat(local.edge_bucket_arns, [for arn in local.edge_bucket_arns : "${arn}/*"])
  }

  # The web app's release role (#283): created and changed here, never passed; GitHub's OIDC token assumes it.
  statement {
    sid = "WebReleaseRole"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:ListInstanceProfilesForRole", "iam:PutRolePolicy",
      "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:UpdateRoleDescription",
    ]
    resources = local.edge_role_arns
  }

  # The account's first load balancer creates Elastic Load Balancing's service-linked role.
  statement {
    sid       = "LoadBalancingServiceLinkedRole"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::${var.account_id}:role/aws-service-role/elasticloadbalancing.amazonaws.com/*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["elasticloadbalancing.amazonaws.com"]
    }
  }

  dynamic "statement" {
    for_each = local.edge_dns_role_prefix == null ? [] : [1]

    content {
      sid       = "WriteOwnNamesInTheSharedZone"
      actions   = ["sts:AssumeRole"]
      resources = ["${local.edge_dns_role_prefix}-deploy"]
    }
  }
}

resource "aws_iam_policy" "edge_read" {
  count = local.edge_enabled ? 1 : 0

  name        = "sft-${local.edge_environment}-terraform-edge-read"
  path        = var.iam_path
  description = "Edge layer: read (#105)"
  policy      = data.aws_iam_policy_document.edge_read[0].json
}

resource "aws_iam_policy" "edge_write" {
  count = local.edge_enabled && var.github_environment != null ? 1 : 0

  name        = "sft-${local.edge_environment}-terraform-edge-write"
  path        = var.iam_path
  description = "Edge layer: create, change and delete (#105)"
  policy      = data.aws_iam_policy_document.edge_write[0].json
}

resource "aws_iam_role_policy_attachment" "plan_edge" {
  count = local.edge_enabled ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.edge_read[0].arn
}

resource "aws_iam_role_policy_attachment" "deploy_edge" {
  for_each = local.edge_enabled && var.github_environment != null ? {
    read  = aws_iam_policy.edge_read[0].arn
    write = aws_iam_policy.edge_write[0].arn
  } : {}

  role       = aws_iam_role.deploy[0].name
  policy_arn = each.value
}
