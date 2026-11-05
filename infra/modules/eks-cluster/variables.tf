# ---------------------------------------------------------------------------------------------------------------------
# Where the cluster lives, from the caller's conventions module
# ---------------------------------------------------------------------------------------------------------------------

variable "environment" {
  description = "The environment, from the caller's conventions module: dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "region" {
  description = "The cluster's Region, from the caller's conventions module: Tokyo or Osaka (NFR-21)."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "account_id" {
  description = "ID of the environment's AWS account. Supplied at plan time, never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "name_prefix" {
  description = "Prefix for regional names, from the conventions module: sft-<env>-<region-short>."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)-apne[13]$", var.name_prefix))
    error_message = "name_prefix must be sft-<dev|staging|prod>-<apne1|apne3>, the conventions module's name_prefix."
  }
}

variable "global_name_prefix" {
  description = "Prefix for global names such as IAM roles, from the conventions module: sft-<env>."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)$", var.global_name_prefix))
    error_message = "global_name_prefix must be sft-<dev|staging|prod>, the conventions module's global_name_prefix."
  }
}

variable "kms_alias_prefix" {
  description = "Prefix of the environment's KMS aliases, from the conventions module: alias/sft/<env> (encryption 4.1)."
  type        = string

  validation {
    condition     = can(regex("^alias/sft/(dev|staging|prod)$", var.kms_alias_prefix))
    error_message = "kms_alias_prefix must be alias/sft/<env>."
  }
}

variable "organization_id" {
  description = "Our AWS Organizations ID. Image pulls and registry key use are limited to its accounts (ADR-0007, T-53)."
  type        = string

  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must be an AWS Organizations ID such as o-abcdefghij."
  }
}

variable "deploy_role_arn" {
  description = "The account's Terraform deploy role, from the conventions module: cluster admin for the cluster-bootstrap layer (ADR-0004)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/sft-bootstrap/sft-(dev|staging|prod)-terraform-deploy$", var.deploy_role_arn))
    error_message = "deploy_role_arn must be the account's sft-<env>-terraform-deploy role under /sft-bootstrap/."
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# IAM: one set of roles per account, used by every cluster in it
# ---------------------------------------------------------------------------------------------------------------------

variable "cluster_regions" {
  description = <<-EOT
    Every Region where this environment has a cluster: dev Tokyo only, staging and prod Tokyo and Osaka. IAM is
    global, so the roles serve every cluster of the account; their trust names each cluster and their policies the
    resources of each Region, so an Osaka failover needs no IAM change (ADR-0004).
  EOT
  type        = list(string)

  validation {
    condition = length(var.cluster_regions) > 0 && alltrue([
      for r in var.cluster_regions : contains(["ap-northeast-1", "ap-northeast-3"], r)
    ])
    error_message = "cluster_regions must hold ap-northeast-1 and, for staging and prod, ap-northeast-3."
  }
}

variable "create_iam" {
  description = <<-EOT
    Create the account's IAM roles, policies and instance profile. True in Tokyo, false in Osaka, which refers to the
    same roles by name, as the bootstrap stacks do for theirs. Osaka's cluster stack is applied after Tokyo's.
  EOT
  type        = bool
}

variable "permissions_boundary_arn" {
  description = <<-EOT
    The workload permissions boundary, a managed policy under /sft-bootstrap/ that the account's bootstrap stack
    creates (terraform-oidc-roles, permissions-cluster.tf). Every role here carries it, and the deploy role may create
    or change these roles only with it, so no apply can mint a role that changes IAM or leaves the design's services.
  EOT
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:policy/sft-bootstrap/sft-(dev|staging|prod)-workload-boundary$", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be the account's /sft-bootstrap/sft-<env>-workload-boundary policy."
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Network, from the network layer's outputs
# ---------------------------------------------------------------------------------------------------------------------

variable "availability_zone_ids" {
  description = "The VPC's AZ IDs, from the network layer. Karpenter's node pools launch only in these."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs by AZ ID, from the network layer: the system node group and Karpenter's nodes."
  type        = map(string)
}

variable "endpoint_subnet_ids" {
  description = "Endpoint subnet IDs by AZ ID, from the network layer: the cluster API's network interfaces (ADR-0021)."
  type        = map(string)
}

variable "security_group_ids" {
  description = "Security group IDs by role, from the network layer: cluster_api, nodes, system_nodes, main_nodes, scan_nodes."
  type        = map(string)

  validation {
    condition     = length(setsubtract(["cluster_api", "nodes", "system_nodes", "main_nodes", "scan_nodes"], keys(var.security_group_ids))) == 0
    error_message = "security_group_ids must hold cluster_api, nodes, system_nodes, main_nodes and scan_nodes."
  }
}

variable "karpenter_discovery_tag" {
  description = "The tag on the private subnets that Karpenter's node classes select, from the network layer."
  type        = map(string)
}

# ---------------------------------------------------------------------------------------------------------------------
# The cluster
# ---------------------------------------------------------------------------------------------------------------------

variable "kubernetes_version" {
  description = <<-EOT
    EKS minor version. Always one in standard support: extended support adds $365 a month per cluster (capacity 7.2).
    Raise it one minor version at a time, staging first, each Osaka cluster with its Tokyo cluster (ADR-0004, T-79).
  EOT
  type        = string

  validation {
    condition     = can(regex("^1\\.[0-9]{2}$", var.kubernetes_version))
    error_message = "kubernetes_version must be a minor version such as 1.37."
  }
}

variable "deletion_protection" {
  description = "Refuse to delete the cluster until an apply turns this off first. On in prod; dev and staging tear down when idle."
  type        = bool
  default     = false
}

variable "control_plane_log_retention_days" {
  description = "Days CloudWatch Logs keeps the control-plane logs, the Kubernetes audit log among them (capacity A33: 90)."
  type        = number
  default     = 90

  validation {
    condition     = contains([30, 60, 90, 120, 150, 180, 365, 400], var.control_plane_log_retention_days)
    error_message = "control_plane_log_retention_days must be a CloudWatch Logs retention period of at least 30 days."
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------------------------------------------------

variable "system_node_count" {
  description = <<-EOT
    Nodes in the always-on system group: 2 in every Tokyo cluster, 1 in an Osaka pilot light, which a failover raises
    to 2 (ADR-0004, capacity 4.2). The group may grow one node above this during an update.
  EOT
  type        = number

  validation {
    condition     = var.system_node_count >= 1 && var.system_node_count <= 3
    error_message = "system_node_count must be 1, 2 or 3."
  }
}

variable "system_instance_type" {
  description = "Instance type of the system node group (capacity 4.2, 4.3: m8g.large, Graviton)."
  type        = string
  default     = "m8g.large"
}

variable "system_volume_size_gib" {
  description = "Size of each system node's Bottlerocket data volume (capacity A28: 20 GB)."
  type        = number
  default     = 20
}

variable "node_pools" {
  description = <<-EOT
    Karpenter's two node pools (capacity 4.2): instance types, the data volume size (A28) and the CPU limit that caps
    how far each pool may grow. The defaults are prod's; dev and staging pass smaller limits.
  EOT
  type = object({
    main = object({
      instance_types    = list(string)
      volume_size_gib   = number
      cpu_limit         = number
      expire_after      = string
      consolidate_after = string
    })
    scan = object({
      instance_types    = list(string)
      volume_size_gib   = number
      cpu_limit         = number
      expire_after      = string
      consolidate_after = string
    })
  })
  default = {
    # 4 nodes at idle, 6 in the peak hour, 8 at 2x design load: 12 nodes of headroom.
    main = { instance_types = ["m8g.xlarge"], volume_size_gib = 100, cpu_limit = 48, expire_after = "720h", consolidate_after = "5m" }
    # 5 at idle, 10 in the peak hour, about 20 at 2x: 24 nodes of headroom.
    scan = { instance_types = ["m8g.xlarge"], volume_size_gib = 50, cpu_limit = 96, expire_after = "720h", consolidate_after = "5m" }
  }
}

variable "bottlerocket_ami_alias" {
  description = "AMI alias the Karpenter node classes use (amiSelectorTerms). Pin a version such as bottlerocket@v1.50.0 to hold nodes on one release."
  type        = string
  default     = "bottlerocket@latest"

  validation {
    condition     = can(regex("^bottlerocket@(latest|v[0-9]+\\.[0-9]+\\.[0-9]+)$", var.bottlerocket_ami_alias))
    error_message = "bottlerocket_ami_alias must be bottlerocket@latest or bottlerocket@vX.Y.Z."
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Access
# ---------------------------------------------------------------------------------------------------------------------

variable "tunnel_extra_hosts" {
  description = <<-EOT
    Hosts besides the cluster API endpoint that the Systems Manager session document may forward to on 443, such as
    Argo CD's internal API server address once cluster-bootstrap gives it one (ADR-0021). Empty by default.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for h in var.tunnel_extra_hosts : can(regex("^[a-z0-9.-]+$", h))])
    error_message = "tunnel_extra_hosts must be plain host names."
  }
}
