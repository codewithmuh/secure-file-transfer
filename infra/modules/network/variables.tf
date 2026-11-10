variable "name_prefix" {
  description = "Prefix for resource names, from the caller's conventions module: sft-<env>-<region-short>."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)-apne[13]$", var.name_prefix))
    error_message = "name_prefix must be sft-<dev|staging|prod>-<apne1|apne3>, the conventions module's name_prefix."
  }
}

variable "region" {
  description = "The VPC's Region, from the caller's conventions module: Tokyo or Osaka (NFR-21)."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "peer_region" {
  description = "The other Region, reached through a cross-Region S3 interface endpoint (ADR-0021). Null for none (dev)."
  type        = string
  default     = null

  validation {
    condition     = var.peer_region == null ? true : contains(["ap-northeast-1", "ap-northeast-3"], var.peer_region) && var.peer_region != var.region
    error_message = "peer_region must be the other of ap-northeast-1 and ap-northeast-3, or null."
  }
}

variable "vpc_cidr_block" {
  description = "The VPC's IPv4 range, a /16 of its own per account and Region (ADR-0021), such as 10.30.0.0/16."
  type        = string

  validation {
    condition     = can(cidrhost(var.vpc_cidr_block, 0)) && can(regex("^10\\.[0-9]{1,3}\\.0\\.0/16$", var.vpc_cidr_block))
    error_message = "vpc_cidr_block must be a /16 inside 10.0.0.0/8, such as 10.30.0.0/16."
  }
}

variable "availability_zone_ids" {
  description = "AZs by ID, not name, so every account gets the same physical zones: two in dev, three elsewhere (ADR-0021)."
  type        = list(string)

  validation {
    condition     = length(var.availability_zone_ids) >= 2 && length(var.availability_zone_ids) <= 3 && length(distinct(var.availability_zone_ids)) == length(var.availability_zone_ids)
    error_message = "availability_zone_ids must hold two or three distinct AZ IDs: the load balancer, EKS and Aurora all need two."
  }

  validation {
    condition = alltrue([
      for id in var.availability_zone_ids :
      can(regex("^${var.region == "ap-northeast-1" ? "apne1" : "apne3"}-az[1-4]$", id))
    ])
    error_message = "Each AZ ID must belong to the VPC's Region, for example apne1-az1 or apne3-az2."
  }
}

variable "nat_gateway_availability_zone_ids" {
  description = "AZs that get a NAT gateway. Null for one in every AZ (staging, prod); dev names one (capacity 5.3)."
  type        = list(string)
  default     = null

  validation {
    condition = var.nat_gateway_availability_zone_ids == null ? true : (
      length(var.nat_gateway_availability_zone_ids) > 0 &&
      length(setsubtract(var.nat_gateway_availability_zone_ids, var.availability_zone_ids)) == 0
    )
    error_message = "nat_gateway_availability_zone_ids must be null or a non-empty subset of availability_zone_ids."
  }
}

variable "interface_endpoint_availability_zone_ids" {
  description = "AZs that get the interface endpoints' network interfaces. Null for every AZ; dev names one (capacity 5.3)."
  type        = list(string)
  default     = null

  validation {
    condition = var.interface_endpoint_availability_zone_ids == null ? true : (
      length(var.interface_endpoint_availability_zone_ids) > 0 &&
      length(setsubtract(var.interface_endpoint_availability_zone_ids, var.availability_zone_ids)) == 0
    )
    error_message = "interface_endpoint_availability_zone_ids must be null or a non-empty subset of availability_zone_ids."
  }
}

variable "organization_id" {
  description = "Our AWS Organizations ID. Endpoint policies admit only its principals and resources (ADR-0021, T-53)."
  type        = string

  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must be an AWS Organizations ID such as o-abcdefghij."
  }
}

variable "endpoints_without_policy" {
  description = <<-EOT
    Interface endpoints whose service takes no endpoint policy, so they keep AWS's default policy. Every endpoint gets
    the organization-scoped policy unless AWS reports the service doesn't support one; a plan then fails until the
    endpoint is listed here, so the exception is recorded, never silent. Keys as in the vpc_endpoint_ids output.
  EOT
  type        = set(string)
  default     = []

  validation {
    condition = length(setsubtract(var.endpoints_without_policy, [
      "sqs", "kms", "secretsmanager", "ecr-api", "ecr-dkr", "sts", "email", "ec2", "eks-auth", "s3-peer",
    ])) == 0
    error_message = "endpoints_without_policy may list only interface endpoint keys (see the vpc_endpoint_ids output)."
  }
}

variable "dns_firewall_allowed_domains" {
  description = <<-EOT
    Names Route 53 Resolver DNS Firewall answers, besides the VPC endpoints' own names, which the module adds itself.
    Everything else gets NXDOMAIN (ADR-0021). "{region}" is replaced with the VPC's Region. The defaults are the
    design's: the cluster API, EC2 host names, and what the egress proxy's listeners and the system nodes' host
    processes reach through NAT.
  EOT
  type        = list(string)
  default = [
    # The cluster API's private endpoint and EC2's own host names inside the VPC.
    "*.{region}.eks.amazonaws.com",
    "*.{region}.compute.internal",
    # Egress proxy, API and notification worker listeners: Cognito's API and managed login (ADR-0021, abuse 3.2).
    "cognito-idp.{region}.amazonaws.com",
    "*.auth.{region}.amazoncognito.com",
    # Egress proxy, Argo CD listener: Git and its notifications.
    "github.com",
    "api.github.com",
    # Egress proxy, signature mirror listener: ClamAV's database.
    "database.clamav.net",
    # Egress proxy, platform listener: AWS APIs with no endpoint here (Karpenter, the load balancer controller,
    # Alertmanager, ADR-0009). Karpenter reads Bottlerocket's AMI IDs from public SSM parameters.
    "eks.{region}.amazonaws.com",
    "elasticloadbalancing.{region}.amazonaws.com",
    "iam.amazonaws.com",
    "monitoring.{region}.amazonaws.com",
    "sns.{region}.amazonaws.com",
    "ssm.{region}.amazonaws.com",
    # Host processes on the system nodes: the Systems Manager agent that ends the cluster tunnel (ADR-0021).
    "ec2messages.{region}.amazonaws.com",
    "ssmmessages.{region}.amazonaws.com",
  ]

  validation {
    condition     = alltrue([for d in var.dns_firewall_allowed_domains : can(regex("^(\\*\\.)?[a-z0-9{}.-]+$", d)) && d != "*"])
    error_message = "Each allowed domain must be a lowercase name, optionally starting with \"*.\"; \"*\" alone would allow everything."
  }
}

variable "dns_firewall_additional_domains" {
  description = "More names for DNS Firewall to answer, such as a custom Cognito domain once it exists. \"{region}\" works here too."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for d in var.dns_firewall_additional_domains : can(regex("^(\\*\\.)?[a-z0-9{}.-]+$", d)) && d != "*"])
    error_message = "Each additional domain must be a lowercase name, optionally starting with \"*.\"; \"*\" alone would allow everything."
  }
}

variable "flow_log_destination_arn" {
  description = <<-EOT
    S3 bucket ARN, optionally with a prefix, for the VPC flow log: the environment's log bucket under the logs key
    (capacity A19, encryption 2.2). Null until that bucket exists: the data layer creates it after the network, so the
    first build applies the network once without a flow log (infra/README.md, "Apply order").
  EOT
  type        = string
  default     = null

  validation {
    condition = var.flow_log_destination_arn == null ? true : can(
      regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](/.*)?$", var.flow_log_destination_arn)
    )
    error_message = "flow_log_destination_arn must be an S3 bucket ARN, optionally followed by /prefix/."
  }
}

variable "service_domain" {
  description = "The environment's service domain: sft.<domain> in prod, <env>.sft.<domain> elsewhere. DNS Firewall answers api. and app. under it, which the synthetic probe calls through the egress proxy (#248, #259). Null leaves them out."
  type        = string
  default     = null

  validation {
    condition     = var.service_domain == null || can(regex("^[a-z0-9.-]+$", var.service_domain))
    error_message = "service_domain must be a lowercase domain name."
  }
}
