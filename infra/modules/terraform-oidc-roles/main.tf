# GitHub Actions' OIDC provider and the Terraform roles for one account (ADR-0005, T-71).
#
# - The plan role trusts only pull requests from this repository. It reads state and writes lock files, nothing more
#   (the state bucket and key policies enforce that).
# - The deploy role trusts only one GitHub environment of this repository. Each environment accepts deployments from
#   main only, so no pull request job can obtain its subject.
# - Both trusts pin the audience and the exact subject with StringEquals, so a wildcard can't creep in.
# - Both roles sit under /sft-bootstrap/, which only the Admin permission set may change (ADR-0006, SCP 4), so no
#   deploy role can widen its own trust.

locals {
  oidc_host = "token.actions.githubusercontent.com"

  oidc_provider_arn = (
    var.create_oidc_provider
    ? aws_iam_openid_connect_provider.github[0].arn
    : "arn:aws:iam::${var.account_id}:oidc-provider/${local.oidc_host}"
  )
}

# AWS validates GitHub's tokens against its own trusted root CAs, so no thumbprint is needed.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "plan_trust" {
  statement {
    sid     = "PullRequestsFromThisRepository"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repository}:pull_request"]
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = var.plan_role_name
  path                 = var.iam_path
  description          = "Terraform plans from pull requests in ${var.github_repository}. Writes only lock files."
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "deploy_trust" {
  count = var.github_environment == null ? 0 : 1

  statement {
    sid     = "OneEnvironmentOfThisRepository"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  count = var.github_environment == null ? 0 : 1

  name                 = var.deploy_role_name
  path                 = var.iam_path
  description          = "Terraform applies from the ${var.github_environment} environment of ${var.github_repository}."
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust[0].json
  max_session_duration = var.deploy_max_session_seconds
}

# PLACEHOLDER (#54). Until the stacks hold resources, each role needs only its state, which the state bucket and key
# policies grant, and the account's Regions and Availability Zones, which every regional stack reads. The issues that
# build each layer replace this with the permissions that layer needs: #55 (organization), #56 (network) and the M4
# issues after them. The deploy role must never get IAM rights over /sft-bootstrap/ (SCP 4 denies them anyway).
data "aws_iam_policy_document" "placeholder" {
  statement {
    sid       = "DescribeRegionsAndZones"
    actions   = ["ec2:DescribeRegions", "ec2:DescribeAvailabilityZones"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "plan_placeholder" {
  name   = "placeholder"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.placeholder.json
}

resource "aws_iam_role_policy" "deploy_placeholder" {
  count = var.github_environment == null ? 0 : 1

  name   = "placeholder"
  role   = aws_iam_role.deploy[0].id
  policy = data.aws_iam_policy_document.placeholder.json
}

# ---------------------------------------------------------------------------------------------------------------------
# Network layer (#56): what the network stacks (modules/network) need, in the Regions of var.network_regions. The plan
# role reads; the deploy role also creates, changes and deletes. Like everything in this module, it changes only through
# an Admin apply of the account's bootstrap stack (SCP 4).
#
# Scoped as tightly as each service allows: Describe and List calls take no resource, so they are limited by Region;
# everything else names resource types in this account and Region. Deletes need the managed-by and project tags that
# every provider adds (default_tags), so the deploy role can't delete network resources it didn't create, such as those
# EKS, Karpenter or the load balancer controller make. Endpoints may be created only for AWS services
# (ec2:VpceServiceOwner), never for another account's endpoint service, which would be a way out of the VPC (T-53).
# ---------------------------------------------------------------------------------------------------------------------

locals {
  network_enabled = length(var.network_regions) > 0

  network_ec2_arns = {
    for type in [
      "elastic-ip", "internet-gateway", "natgateway", "route-table", "security-group", "security-group-rule", "subnet",
      "vpc", "vpc-endpoint", "vpc-flow-log",
    ] :
    type => [for region in var.network_regions : "arn:aws:ec2:${region}:${var.account_id}:${type}/*"]
  }

  # Security group rules toward S3 name its AWS-managed prefix list.
  network_aws_prefix_list_arns = [for region in var.network_regions : "arn:aws:ec2:${region}:aws:prefix-list/*"]

  network_resolver_arns = [for region in var.network_regions : "arn:aws:route53resolver:${region}:${var.account_id}:*"]
}

data "aws_iam_policy_document" "network_read" {
  count = local.network_enabled ? 1 : 0

  statement {
    sid = "NetworkDescribe"
    actions = [
      "ec2:DescribeAddresses",
      "ec2:DescribeAddressesAttribute",
      "ec2:DescribeFlowLogs",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeManagedPrefixLists",
      "ec2:DescribeNatGateways",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribePrefixLists",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcAttribute",
      "ec2:DescribeVpcEndpointServices",
      "ec2:DescribeVpcEndpoints",
      "ec2:DescribeVpcs",
      "route53resolver:ListFirewallConfigs",
      "route53resolver:ListFirewallDomainLists",
      "route53resolver:ListFirewallRuleGroupAssociations",
      "route53resolver:ListFirewallRuleGroups",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid = "DnsFirewallRead"
    actions = [
      "route53resolver:GetFirewallConfig",
      "route53resolver:GetFirewallDomainList",
      "route53resolver:GetFirewallRuleGroup",
      "route53resolver:GetFirewallRuleGroupAssociation",
      "route53resolver:ListFirewallDomains",
      "route53resolver:ListFirewallRules",
      "route53resolver:ListTagsForResource",
    ]
    resources = local.network_resolver_arns
  }

  # The endpoint policies name our organization (ADR-0021); its ID is read, never committed. Organizations is a global
  # service, so no Region condition.
  statement {
    sid       = "ReadOrganizationId"
    actions   = ["organizations:DescribeOrganization"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "network_deploy" {
  count = local.network_enabled ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.network_read[0].json]

  statement {
    sid = "NetworkCreateAndChange"
    actions = [
      "ec2:AllocateAddress",
      "ec2:AssociateRouteTable",
      "ec2:AttachInternetGateway",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateFlowLogs",
      "ec2:CreateInternetGateway",
      "ec2:CreateNatGateway",
      "ec2:CreateRoute",
      "ec2:CreateRouteTable",
      "ec2:CreateSecurityGroup",
      "ec2:CreateSubnet",
      "ec2:CreateTags",
      "ec2:CreateVpc",
      "ec2:DeleteRoute",
      "ec2:DeleteTags",
      "ec2:DisassociateRouteTable",
      "ec2:ModifySecurityGroupRules",
      "ec2:ModifySubnetAttribute",
      "ec2:ModifyVpcAttribute",
      "ec2:ReplaceRoute",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
    ]
    resources = concat(
      flatten([
        for type in [
          "elastic-ip", "internet-gateway", "natgateway", "route-table", "security-group", "security-group-rule",
          "subnet", "vpc", "vpc-flow-log",
        ] : local.network_ec2_arns[type]
      ]),
      local.network_aws_prefix_list_arns,
    )
  }

  # The endpoint itself: AWS services only.
  statement {
    sid       = "CreateEndpointsForAwsServicesOnly"
    actions   = ["ec2:CreateVpcEndpoint"]
    resources = local.network_ec2_arns["vpc-endpoint"]

    condition {
      test     = "StringEquals"
      variable = "ec2:VpceServiceOwner"
      values   = ["amazon"]
    }
  }

  # The VPC, subnets, security groups and route tables an endpoint is created in or changed to use.
  statement {
    sid     = "AttachEndpoints"
    actions = ["ec2:CreateVpcEndpoint", "ec2:ModifyVpcEndpoint"]
    resources = flatten([
      for type in ["route-table", "security-group", "subnet", "vpc"] : local.network_ec2_arns[type]
    ])
  }

  statement {
    sid = "DeleteOrChangeOwnNetworkResources"
    actions = [
      "ec2:DeleteFlowLogs",
      "ec2:DeleteInternetGateway",
      "ec2:DeleteNatGateway",
      "ec2:DeleteRouteTable",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteSubnet",
      "ec2:DeleteVpc",
      "ec2:DeleteVpcEndpoints",
      "ec2:DetachInternetGateway",
      "ec2:ModifyVpcEndpoint",
      "ec2:ReleaseAddress",
    ]
    resources = flatten([
      for type in [
        "elastic-ip", "internet-gateway", "natgateway", "route-table", "security-group", "subnet", "vpc",
        "vpc-endpoint", "vpc-flow-log",
      ] : local.network_ec2_arns[type]
    ])

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/managed-by"
      values   = ["terraform"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/project"
      values   = ["secure-file-transfer"]
    }
  }

  # Flow logs to S3 go through CloudWatch Logs' delivery service, whose actions take no resource.
  statement {
    sid       = "FlowLogDelivery"
    actions   = ["logs:CreateLogDelivery", "logs:DeleteLogDelivery"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  # Only DNS Firewall's actions: never Resolver endpoints or forwarding rules, which could send queries out.
  statement {
    sid = "DnsFirewallWrite"
    actions = [
      "route53resolver:AssociateFirewallRuleGroup",
      "route53resolver:CreateFirewallDomainList",
      "route53resolver:CreateFirewallRule",
      "route53resolver:CreateFirewallRuleGroup",
      "route53resolver:DeleteFirewallDomainList",
      "route53resolver:DeleteFirewallRule",
      "route53resolver:DeleteFirewallRuleGroup",
      "route53resolver:DisassociateFirewallRuleGroup",
      "route53resolver:TagResource",
      "route53resolver:UntagResource",
      "route53resolver:UpdateFirewallConfig",
      "route53resolver:UpdateFirewallDomains",
      "route53resolver:UpdateFirewallRule",
      "route53resolver:UpdateFirewallRuleGroupAssociation",
    ]
    resources = local.network_resolver_arns
  }

  # An interface endpoint to S3 in the other Region (ADR-0021). A permission-only action, which the SCPs must allow
  # too; the IfExists condition limits the service Region where the key is present.
  dynamic "statement" {
    for_each = length(var.network_regions) > 1 ? [1] : []

    content {
      sid       = "CrossRegionEndpoints"
      actions   = ["vpce:AllowMultiRegion"]
      resources = ["*"]

      condition {
        test     = "StringEquals"
        variable = "aws:RequestedRegion"
        values   = var.network_regions
      }

      condition {
        test     = "StringEqualsIfExists"
        variable = "ec2:VpceServiceRegion"
        values   = var.network_regions
      }
    }
  }
}

resource "aws_iam_role_policy" "plan_network" {
  count = local.network_enabled ? 1 : 0

  name   = "network"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.network_read[0].json
}

resource "aws_iam_role_policy" "deploy_network" {
  count = local.network_enabled && var.github_environment != null ? 1 : 0

  name   = "network"
  role   = aws_iam_role.deploy[0].id
  policy = data.aws_iam_policy_document.network_deploy[0].json
}
