# VPC endpoints (ADR-0021, architecture 3.1, T-53): the S3 gateway endpoint and the interface endpoints, so sending
# email, the security-critical writes to the other Region and the nodes need neither NAT nor the egress proxy.
#
# Every endpoint policy admits only principals in our organization (aws:PrincipalOrgID) acting on resources in our
# organization (aws:ResourceOrgID), the data perimeter pattern AWS publishes for VPC endpoints. A pod holding another
# account's credentials, or writing to another account's bucket, queue or key, fails at the endpoint.
#
# A request that targets no resource, such as ecr:GetAuthorizationToken, sts:GetCallerIdentity or EC2's Describe
# calls, may carry no aws:ResourceOrgID, and StringEquals on a missing key is false. So each endpoint also lets our
# principals make its few resourceless read calls, named one by one in unscoped_actions, on the principal check alone.
# Not StringEqualsIfExists on the resource check: that would also pass a resource whose account is in no organization,
# which is what an attacker's own bucket or queue looks like (T-53).
#
# The other exceptions are AWS-owned resources the platform needs, each named below:
#   - ECR: the AWS-owned registries that serve the EKS add-ons, the pause image and Bottlerocket's host containers,
#     pull actions only (ADR-0004, ADR-0007);
#   - EC2: launching nodes from Bottlerocket's AWS-owned AMIs (Karpenter);
#   - S3 gateway: ECR's layer bucket, which serves the layers of our registry and those registries alike.
# Endpoint policies grant nothing: IAM, key and bucket policies still decide what each principal may do.

locals {
  # The AWS-owned registry accounts ADR-0021 names, for both Regions. A new add-on from another registry must be added
  # here, and to Kyverno's image policy (ADR-0007). Sources: the EKS user guide's add-on image registries, and
  # Bottlerocket's ECR registry map (bottlerocket-core-kit, schnauzer helpers), checked 2026-11-04.
  aws_owned_registries = {
    "ap-northeast-1" = [
      "602401143452", # aws-owned-account: Amazon EKS add-on images and the pause image, ap-northeast-1
      "328549459982", # aws-owned-account: Bottlerocket host containers (control, admin), ap-northeast-1
    ]
    "ap-northeast-3" = [
      "602401143452", # aws-owned-account: Amazon EKS add-on images and the pause image, ap-northeast-3
      "328549459982", # aws-owned-account: Bottlerocket host containers (control, admin), ap-northeast-3
    ]
  }

  aws_owned_repository_arns = sort(flatten([
    for region, accounts in local.aws_owned_registries : [
      for account in accounts : "arn:aws:ecr:${region}:${account}:repository/*"
    ]
  ]))

  # ECR keeps every image layer, ours and AWS's, in one AWS-owned bucket per Region.
  ecr_layer_bucket_arn = "arn:aws:s3:::prod-${var.region}-starport-layer-bucket"

  # Interface endpoints: the six of architecture 3.1 and the four ADR-0021 added (SES's API, EC2, EKS Auth and S3 in
  # the other Region). dns_names are the names private DNS answers inside the VPC; DNS Firewall allows them
  # (dns-firewall.tf). The cross-Region endpoint has regional DNS only (no zonal names), which is all clients use.
  interface_endpoints = merge(
    {
      "sqs" = {
        service_name     = "com.amazonaws.${var.region}.sqs"
        service_region   = null
        dns_names        = ["sqs.${var.region}.amazonaws.com"]
        unscoped_actions = ["sqs:ListQueues"]
      }
      "kms" = {
        service_name     = "com.amazonaws.${var.region}.kms"
        service_region   = null
        dns_names        = ["kms.${var.region}.amazonaws.com"]
        unscoped_actions = ["kms:ListAliases", "kms:ListKeys"]
      }
      "secretsmanager" = {
        service_name     = "com.amazonaws.${var.region}.secretsmanager"
        service_region   = null
        dns_names        = ["secretsmanager.${var.region}.amazonaws.com"]
        unscoped_actions = ["secretsmanager:ListSecrets"]
      }
      "ecr-api" = {
        service_name     = "com.amazonaws.${var.region}.ecr.api"
        service_region   = null
        dns_names        = ["api.ecr.${var.region}.amazonaws.com"]
        unscoped_actions = ["ecr:GetAuthorizationToken"]
      }
      "ecr-dkr" = {
        service_name     = "com.amazonaws.${var.region}.ecr.dkr"
        service_region   = null
        dns_names        = ["dkr.ecr.${var.region}.amazonaws.com", "*.dkr.ecr.${var.region}.amazonaws.com"]
        unscoped_actions = ["ecr:GetAuthorizationToken"]
      }
      "sts" = {
        service_name     = "com.amazonaws.${var.region}.sts"
        service_region   = null
        dns_names        = ["sts.${var.region}.amazonaws.com"]
        unscoped_actions = ["sts:GetCallerIdentity"]
      }
      # SES's API (SESv2), not its SMTP interface.
      "email" = {
        service_name     = "com.amazonaws.${var.region}.email"
        service_region   = null
        dns_names        = ["email.${var.region}.amazonaws.com"]
        unscoped_actions = ["ses:GetAccount"]
      }
      "ec2" = {
        service_name     = "com.amazonaws.${var.region}.ec2"
        service_region   = null
        dns_names        = ["ec2.${var.region}.amazonaws.com"]
        unscoped_actions = ["ec2:Describe*"]
      }
      # EKS Pod Identity: the agent on every node exchanges service account tokens here.
      "eks-auth" = {
        service_name     = "com.amazonaws.${var.region}.eks-auth"
        service_region   = null
        dns_names        = ["eks-auth.${var.region}.api.aws"]
        unscoped_actions = []
      }
    },
    var.peer_region == null ? {} : {
      # S3 in the other Region: the API's security-critical writes to the other archive, Osaka's deletes (ADR-0021).
      "s3-peer" = {
        service_name     = "com.amazonaws.${var.peer_region}.s3"
        service_region   = var.peer_region
        dns_names        = ["s3.${var.peer_region}.amazonaws.com", "*.s3.${var.peer_region}.amazonaws.com"]
        unscoped_actions = []
      }
    },
  )

  ecr_endpoints = toset(["ecr-api", "ecr-dkr"])

  interface_endpoint_az_ids = toset(coalesce(var.interface_endpoint_availability_zone_ids, var.availability_zone_ids))
}

# What AWS says about each service in this Region: the plan fails here if a service name doesn't exist, and
# vpc_endpoint_policy_supported settles whether the service takes a policy (ADR-0021 left SES's open for this slice).
data "aws_vpc_endpoint_service" "interface" {
  for_each = local.interface_endpoints

  service_name    = each.value.service_name
  service_type    = "Interface"
  service_regions = each.value.service_region == null ? null : [each.value.service_region]
}

# ---------------------------------------------------------------------------------------------------------------------
# Interface endpoint policies
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "interface_endpoint" {
  for_each = local.interface_endpoints

  statement {
    sid       = "OrganizationPrincipalsToOrganizationResources"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceOrgID"
      values   = [var.organization_id]
    }
  }

  # Calls that target no resource, so carry no aws:ResourceOrgID (see the top of this file). Read-only; the actions
  # are listed per endpoint in local.interface_endpoints.
  dynamic "statement" {
    for_each = length(each.value.unscoped_actions) > 0 ? [1] : []

    content {
      sid       = "OrganizationPrincipalsCallsWithoutResource"
      effect    = "Allow"
      actions   = each.value.unscoped_actions
      resources = ["*"]

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [var.organization_id]
      }
    }
  }

  # Nodes pull the EKS add-on images, the pause image and Bottlerocket's host containers from AWS-owned registries.
  # Pull actions only, and only those registries' repositories.
  dynamic "statement" {
    for_each = contains(local.ecr_endpoints, each.key) ? [1] : []

    content {
      sid    = "OrganizationPrincipalsPullFromAwsOwnedRegistries"
      effect = "Allow"
      actions = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
      ]
      resources = local.aws_owned_repository_arns

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [var.organization_id]
      }
    }
  }

  # Karpenter launches nodes from Bottlerocket's public AMIs, which AWS owns. A launch authorizes the image as one of
  # its resources, so the image fails aws:ResourceOrgID; this lets our principals launch from AMIs in this Region.
  dynamic "statement" {
    for_each = each.key == "ec2" ? [1] : []

    content {
      sid       = "OrganizationPrincipalsLaunchFromAwsOwnedImages"
      effect    = "Allow"
      actions   = ["ec2:CreateFleet", "ec2:RunInstances"]
      resources = ["arn:aws:ec2:${var.region}::image/*"]

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [var.organization_id]
      }
    }
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.this.id
  vpc_endpoint_type   = "Interface"
  service_name        = each.value.service_name
  service_region      = each.value.service_region
  ip_address_type     = "ipv4"
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.endpoints.id]
  subnet_ids          = [for id in sort(local.interface_endpoint_az_ids) : aws_subnet.endpoints[id].id]

  policy = (
    data.aws_vpc_endpoint_service.interface[each.key].vpc_endpoint_policy_supported
    ? data.aws_iam_policy_document.interface_endpoint[each.key].json
    : null
  )

  # S3's interface endpoint would otherwise answer private DNS only for inbound Resolver endpoints, which needs a
  # gateway endpoint for the same service; the one here is for this Region's S3, not the other's.
  dynamic "dns_options" {
    for_each = each.key == "s3-peer" ? [1] : []

    content {
      dns_record_ip_type                             = "ipv4"
      private_dns_only_for_inbound_resolver_endpoint = false
    }
  }

  tags = {
    Name      = "${var.name_prefix}-vpce-${each.key}"
    component = "vpc-endpoints"
  }

  lifecycle {
    precondition {
      condition = (
        data.aws_vpc_endpoint_service.interface[each.key].vpc_endpoint_policy_supported
        || contains(var.endpoints_without_policy, each.key)
      )
      error_message = <<-EOT
        ${each.value.service_name} takes no endpoint policy. List "${each.key}" in endpoints_without_policy and record
        why in ADR-0021.
      EOT
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# S3 gateway endpoint: S3 in this Region, for our buckets and ECR's layer bucket
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "s3_gateway" {
  statement {
    sid       = "OrganizationPrincipalsToOrganizationBuckets"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceOrgID"
      values   = [var.organization_id]
    }
  }

  # Image layers, from our registry and the AWS-owned ones, come from ECR's bucket through URLs ECR presigns with its
  # own credentials, so the request's principal is ECR's, never ours, and this statement can't name our organization.
  # It stays inside T-53: GetObject on that one AWS-owned bucket only (ECR's documented minimum), which can read a
  # layer ECR has authorized but can't write anything out.
  statement {
    sid       = "EcrImageLayers"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${local.ecr_layer_bucket_arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint" "s3_gateway" {
  vpc_id            = aws_vpc.this.id
  vpc_endpoint_type = "Gateway"
  service_name      = "com.amazonaws.${var.region}.s3"
  route_table_ids   = [for id in sort(local.az_ids) : aws_route_table.private[id].id]
  policy            = data.aws_iam_policy_document.s3_gateway.json

  tags = {
    Name = "${var.name_prefix}-vpce-s3-gateway"
  }
}
